#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <map>
#include <deque>
#include <algorithm>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define TYPE_SYN 1
#define TYPE_SYN_ACK 2
#define TYPE_ACK 3
#define TYPE_DATA 4

#define RETRANSMIT_INTERVAL_NS 100000000L
#define HANDSHAKE_TIMEOUT_US 200000
#define SEND_BUFFER_CAPACITY (256 * 1024)
#define FAST_RETRANSMIT_THRESHOLD 3

static const int MAX_PAYLOAD = MAX_SEGMENT_SIZE - (int)sizeof(struct poli_tcp_data_hdr);

struct inflight_segment {
    uint16_t seq_num;
    int total_len;
    char bytes[MAX_SEGMENT_SIZE];
};

struct sender_state {
    uint16_t next_seq;
    int congestion_window;
    int peer_window;
    bool acked_since_tick;
    uint16_t last_ack_num;
    int duplicate_acks;
    deque<inflight_segment> window;
    deque<char> pending;
};

std::map<int, struct connection *> cons;
std::map<int, struct sender_state> senders;

struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;

static int link_speed_mbps = 0;
static int link_delay_ms = 0;

static int compute_congestion_window()
{
    long bytes_per_sec = (long)link_speed_mbps * 1000000 / 8;
    double rtt_seconds = 2.0 * link_delay_ms / 1000.0;
    long bdp_bytes = (long)(bytes_per_sec * rtt_seconds);
    int segments = (int)(bdp_bytes / MAX_PAYLOAD);
    if (segments < 1)
        segments = 1;
    int window = segments * 2;
    if (window < 64)
        window = 64;
    return window;
}

static int effective_window(struct sender_state &state)
{
    return min(state.congestion_window, state.peer_window);
}

static void transmit_segment(int conn_id, struct inflight_segment &segment)
{
    struct connection *con = cons[conn_id];
    sendto(con->sockfd, segment.bytes, segment.total_len, 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
}

static void pump_pending(int conn_id)
{
    struct sender_state &state = senders[conn_id];

    while ((int)state.window.size() < effective_window(state) && !state.pending.empty()) {
        int payload_len = min((int)state.pending.size(), MAX_PAYLOAD);

        struct inflight_segment segment;
        struct poli_tcp_data_hdr *header = (struct poli_tcp_data_hdr *)segment.bytes;
        header->protocol_id = POLI_PROTOCOL_ID;
        header->conn_id = conn_id;
        header->type = TYPE_DATA;
        header->seq_num = state.next_seq;
        header->len = payload_len;

        for (int i = 0; i < payload_len; i++) {
            segment.bytes[sizeof(struct poli_tcp_data_hdr) + i] = state.pending.front();
            state.pending.pop_front();
        }
        segment.seq_num = state.next_seq;
        segment.total_len = sizeof(struct poli_tcp_data_hdr) + payload_len;

        transmit_segment(conn_id, segment);
        state.window.push_back(segment);
        state.next_seq++;
    }
}

int send_data(int conn_id, char *buffer, int len)
{
    pthread_mutex_lock(&cons[conn_id]->con_lock);

    struct sender_state &state = senders[conn_id];

    if ((int)state.pending.size() >= SEND_BUFFER_CAPACITY) {
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        return -1;
    }

    for (int i = 0; i < len; i++)
        state.pending.push_back(buffer[i]);

    pump_pending(conn_id);

    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return len;
}

static void handle_ack(int conn_id, char *buffer, int len)
{
    if (len < (int)sizeof(struct poli_tcp_ctrl_hdr))
        return;

    struct poli_tcp_ctrl_hdr *header = (struct poli_tcp_ctrl_hdr *)buffer;
    if (header->protocol_id != POLI_PROTOCOL_ID || header->type != TYPE_ACK)
        return;

    struct sender_state &state = senders[conn_id];
    uint16_t ack_num = header->ack_num;

    if (ack_num > state.last_ack_num) {
        while (!state.window.empty() && state.window.front().seq_num < ack_num)
            state.window.pop_front();
        state.last_ack_num = ack_num;
        state.duplicate_acks = 0;
        state.acked_since_tick = true;
    } else if (ack_num == state.last_ack_num) {
        state.duplicate_acks++;
        if (state.duplicate_acks >= FAST_RETRANSMIT_THRESHOLD && !state.window.empty()) {
            transmit_segment(conn_id, state.window.front());
            state.duplicate_acks = 0;
        }
    }

    state.peer_window = header->recv_window;
    pump_pending(conn_id);
}

static void handle_timeout(int conn_id)
{
    struct sender_state &state = senders[conn_id];

    if (!state.window.empty() && !state.acked_since_tick) {
        for (size_t i = 0; i < state.window.size(); i++)
            transmit_segment(conn_id, state.window[i]);
    }

    state.acked_since_tick = false;
    pump_pending(conn_id);
}

void *sender_handler(void *arg)
{
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {

        pthread_mutex_lock(&registry_lock);
        size_t active = cons.size();
        pthread_mutex_unlock(&registry_lock);
        if (active == 0) {
            usleep(1000);
            continue;
        }
        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&registry_lock);
        struct connection *con = cons.count(conn_id) ? cons[conn_id] : NULL;
        pthread_mutex_unlock(&registry_lock);
        if (con == NULL)
            continue;

        pthread_mutex_lock(&con->con_lock);

        if (res >= (int)sizeof(struct poli_tcp_ctrl_hdr))
            handle_ack(conn_id, buf, res);
        else
            handle_timeout(conn_id);

        pthread_mutex_unlock(&con->con_lock);
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    pthread_mutex_lock(&registry_lock);
    int conn_id = fdmax;
    pthread_mutex_unlock(&registry_lock);

    con->conn_id = conn_id;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(&con->servaddr, 0, sizeof(con->servaddr));
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_addr.s_addr = ip;
    con->servaddr.sin_port = port;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = HANDSHAKE_TIMEOUT_US;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct poli_tcp_ctrl_hdr syn;
    memset(&syn, 0, sizeof(syn));
    syn.protocol_id = POLI_PROTOCOL_ID;
    syn.conn_id = conn_id;
    syn.type = TYPE_SYN;

    char reply[MAX_SEGMENT_SIZE];
    uint16_t data_port = 0;
    int initial_peer_window = 1;

    while (1) {
        sendto(con->sockfd, &syn, sizeof(syn), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(con->sockfd, reply, sizeof(reply), 0, (struct sockaddr *)&from, &from_len);
        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr))
            continue;

        struct poli_tcp_ctrl_hdr *header = (struct poli_tcp_ctrl_hdr *)reply;
        if (header->protocol_id == POLI_PROTOCOL_ID && header->type == TYPE_SYN_ACK) {
            memcpy(&data_port, reply + sizeof(struct poli_tcp_ctrl_hdr), sizeof(uint16_t));
            initial_peer_window = header->recv_window > 0 ? header->recv_window : 1;
            break;
        }
    }

    con->servaddr.sin_port = data_port;

    struct poli_tcp_ctrl_hdr ack;
    memset(&ack, 0, sizeof(ack));
    ack.protocol_id = POLI_PROTOCOL_ID;
    ack.conn_id = conn_id;
    ack.type = TYPE_ACK;
    sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_init(&con->con_lock, NULL);

    struct sender_state state;
    state.next_seq = 0;
    state.congestion_window = compute_congestion_window();
    state.peer_window = initial_peer_window;
    state.acked_since_tick = false;
    state.last_ack_num = 0;
    state.duplicate_acks = 0;

    int timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = RETRANSMIT_INTERVAL_NS;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = RETRANSMIT_INTERVAL_NS;
    timerfd_settime(timer_fd, 0, &spec, NULL);

    pthread_mutex_lock(&registry_lock);
    cons.insert({conn_id, con});
    senders[conn_id] = state;
    int slot = fdmax;
    data_fds[slot].fd = con->sockfd;
    data_fds[slot].events = POLLIN;
    timer_fds[slot].fd = timer_fd;
    timer_fds[slot].events = POLLIN;
    __atomic_store_n(&fdmax, slot + 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&registry_lock);


    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;

    link_speed_mbps = speed;
    link_delay_ms = delay;

    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}