#include <pthread.h>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <map>
#include <deque>
#include <vector>
#include <algorithm>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
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

static const int MAX_PAYLOAD = MAX_SEGMENT_SIZE - (int)sizeof(struct poli_tcp_data_hdr);

struct receiver_state {
    uint16_t expected_seq;
    int capacity_bytes;
    int buffered_bytes;
    struct sockaddr_in peer;
    pthread_cond_t data_ready;
    std::map<uint16_t, std::vector<char>> out_of_order;
    std::deque<char> ready_bytes;
};

std::map<int, struct connection *> cons;
std::map<int, struct receiver_state> receivers;

struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;

static int listen_fd = -1;
static bool listen_bound = false;
static int receiver_buffer_bytes = 0;

static uint16_t free_window(struct receiver_state &state)
{
    int free_bytes = state.capacity_bytes - state.buffered_bytes;
    if (free_bytes < 0)
        free_bytes = 0;
    int segments = free_bytes / MAX_PAYLOAD;
    if (segments > 65535)
        segments = 65535;
    return (uint16_t)segments;
}

static void send_cumulative_ack(struct connection *con, struct receiver_state *state)
{
    struct poli_tcp_ctrl_hdr ack;
    memset(&ack, 0, sizeof(ack));
    ack.protocol_id = POLI_PROTOCOL_ID;
    ack.conn_id = con->conn_id;
    ack.type = TYPE_ACK;
    ack.ack_num = state->expected_seq;
    ack.recv_window = free_window(*state);

    sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&state->peer, sizeof(state->peer));
}

static void deliver_in_order_bytes(struct receiver_state &state, const char *payload, int len)
{
    for (int i = 0; i < len; i++)
        state.ready_bytes.push_back(payload[i]);
}

static void process_data_segment(struct connection *con, struct receiver_state *st, char *segment, int total_len)
{
    struct receiver_state &state = *st;

    struct poli_tcp_data_hdr *header = (struct poli_tcp_data_hdr *)segment;
    uint16_t seq = header->seq_num;
    int payload_len = header->len;
    char *payload = segment + sizeof(struct poli_tcp_data_hdr);

    if (seq == state.expected_seq) {
        deliver_in_order_bytes(state, payload, payload_len);
        state.buffered_bytes += payload_len;
        state.expected_seq++;

        while (state.out_of_order.count(state.expected_seq) > 0) {
            std::vector<char> &buffered = state.out_of_order[state.expected_seq];
            state.ready_bytes.insert(state.ready_bytes.end(), buffered.begin(), buffered.end());
            state.out_of_order.erase(state.expected_seq);
            state.expected_seq++;
        }

        pthread_cond_signal(&state.data_ready);
    } else if (seq > state.expected_seq) {
        if (state.out_of_order.count(seq) == 0 && state.buffered_bytes + payload_len <= state.capacity_bytes) {
            state.out_of_order[seq] = std::vector<char>(payload, payload + payload_len);
            state.buffered_bytes += payload_len;
        }
    }

    send_cumulative_ack(con, st);
}

int recv_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&registry_lock);
    struct connection *con = cons[conn_id];
    struct receiver_state *st = &receivers[conn_id];
    pthread_mutex_unlock(&registry_lock);

    pthread_mutex_lock(&con->con_lock);

    struct receiver_state &state = *st;

    while (state.ready_bytes.empty())
        pthread_cond_wait(&state.data_ready, &con->con_lock);

    size = min(len, (int)state.ready_bytes.size());
    for (int i = 0; i < size; i++) {
        buffer[i] = state.ready_bytes.front();
        state.ready_bytes.pop_front();
    }
    state.buffered_bytes -= size;

    send_cumulative_ack(con, st);

    pthread_mutex_unlock(&con->con_lock);

    return size;
}

void *receiver_handler(void *arg)
{
    char segment[MAX_SEGMENT_SIZE];
    int res;

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
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&registry_lock);
        struct connection *con = cons.count(conn_id) ? cons[conn_id] : NULL;
        struct receiver_state *st = (con && receivers.count(conn_id)) ? &receivers[conn_id] : NULL;
        pthread_mutex_unlock(&registry_lock);
        if (con == NULL || st == NULL)
            continue;

        pthread_mutex_lock(&con->con_lock);

        if (res >= (int)sizeof(struct poli_tcp_data_hdr)) {
            struct poli_tcp_data_hdr *header = (struct poli_tcp_data_hdr *)segment;
            if (header->protocol_id == POLI_PROTOCOL_ID && header->type == TYPE_DATA)
                process_data_segment(con, st, segment, res);
        } else {
            send_cumulative_ack(con, st);
        }

        pthread_mutex_unlock(&con->con_lock);
    }
}

static void receive_syn(struct sockaddr_in *client, socklen_t *client_len)
{
    char buf[MAX_SEGMENT_SIZE];

    while (1) {
        *client_len = sizeof(struct sockaddr_in);
        int n = recvfrom(listen_fd, buf, sizeof(buf), 0, (struct sockaddr *)client, client_len);
        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr))
            continue;

        struct poli_tcp_ctrl_hdr *header = (struct poli_tcp_ctrl_hdr *)buf;
        if (header->protocol_id == POLI_PROTOCOL_ID && header->type == TYPE_SYN)
            return;
    }
}

int wait4connect(uint32_t ip, uint16_t port)
{
    if (!listen_bound) {
        listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in listen_addr;
        memset(&listen_addr, 0, sizeof(listen_addr));
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_addr.s_addr = ip;
        listen_addr.sin_port = port;
        bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr));
        listen_bound = true;
    }

    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);
    receive_syn(&client, &client_len);

    pthread_mutex_lock(&registry_lock);
    int conn_id = fdmax;
    pthread_mutex_unlock(&registry_lock);

    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    con->conn_id = conn_id;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = 0;
    bind(con->sockfd, (struct sockaddr *)&data_addr, sizeof(data_addr));

    struct sockaddr_in assigned;
    socklen_t assigned_len = sizeof(assigned);
    getsockname(con->sockfd, (struct sockaddr *)&assigned, &assigned_len);
    uint16_t data_port = assigned.sin_port;

    con->servaddr = client;

    pthread_mutex_init(&con->con_lock, NULL);

    struct receiver_state state;
    state.expected_seq = 0;
    state.capacity_bytes = receiver_buffer_bytes;
    state.buffered_bytes = 0;
    state.peer = client;
    pthread_cond_init(&state.data_ready, NULL);

    pthread_mutex_lock(&registry_lock);
    cons.insert({conn_id, con});
    receivers[conn_id] = state;
    struct receiver_state *st = &receivers[conn_id];
    pthread_mutex_unlock(&registry_lock);

    char syn_ack[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t)];
    struct poli_tcp_ctrl_hdr *syn_ack_header = (struct poli_tcp_ctrl_hdr *)syn_ack;
    memset(syn_ack_header, 0, sizeof(struct poli_tcp_ctrl_hdr));
    syn_ack_header->protocol_id = POLI_PROTOCOL_ID;
    syn_ack_header->conn_id = conn_id;
    syn_ack_header->type = TYPE_SYN_ACK;
    syn_ack_header->recv_window = free_window(*st);
    memcpy(syn_ack + sizeof(struct poli_tcp_ctrl_hdr), &data_port, sizeof(uint16_t));

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = HANDSHAKE_TIMEOUT_US;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char first_segment[MAX_SEGMENT_SIZE];
    int first_len = 0;
    bool first_is_data = false;

    while (1) {
        sendto(con->sockfd, syn_ack, sizeof(syn_ack), 0, (struct sockaddr *)&client, sizeof(client));

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(con->sockfd, first_segment, sizeof(first_segment), 0, (struct sockaddr *)&from, &from_len);
        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr))
            continue;

        con->servaddr = from;
        st->peer = from;

        struct poli_tcp_data_hdr *data_header = (struct poli_tcp_data_hdr *)first_segment;
        if (data_header->protocol_id == POLI_PROTOCOL_ID && data_header->type == TYPE_DATA) {
            first_is_data = true;
            first_len = n;
            break;
        }

        struct poli_tcp_ctrl_hdr *ctrl_header = (struct poli_tcp_ctrl_hdr *)first_segment;
        if (ctrl_header->protocol_id == POLI_PROTOCOL_ID && ctrl_header->type == TYPE_ACK)
            break;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (first_is_data) {
        pthread_mutex_lock(&con->con_lock);
        process_data_segment(con, st, first_segment, first_len);
        pthread_mutex_unlock(&con->con_lock);
    }

    int timer_fd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = RETRANSMIT_INTERVAL_NS;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = RETRANSMIT_INTERVAL_NS;
    timerfd_settime(timer_fd, 0, &spec, NULL);

    pthread_mutex_lock(&registry_lock);
    int slot = fdmax;
    data_fds[slot].fd = con->sockfd;
    data_fds[slot].events = POLLIN;
    timer_fds[slot].fd = timer_fd;
    timer_fds[slot].events = POLLIN;
    __atomic_store_n(&fdmax, slot + 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&registry_lock);


    return conn_id;
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;

    receiver_buffer_bytes = recv_buffer_bytes;

    ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}