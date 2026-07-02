# Reliable Transport Protocol over UDP

A reliable, connection-oriented byte-stream protocol built on top of UDP: a three-way handshake for connection setup, a sliding window with cumulative acknowledgments and flow control, loss recovery through timeouts and fast retransmit, and support for multiple concurrent connections.

## Opening the connection

Before data transmission begins, the protocol performs a three-way handshake. The client sends a SYN and keeps resending it until it gets a response. The server, in `wait4connect`, listens on the well-known port, and when it sees a SYN it opens a new socket on a free port (binding to port `0` and then calling `getsockname` to find out which port the system assigned). The server places this new port directly in the payload of the SYN-ACK. The client reads it, switches its destination to that port, and sends the final ACK, after which all communication happens between this pair of sockets.

To avoid losing anything if the final ACK goes astray, the server also accepts the first data segment that arrives on the new socket as confirmation, and processes it immediately in that case. This keeps the listening socket free, so the server can comfortably accept other clients in parallel.

## The window and acknowledgments

Each data segment carries a sequence number. The receiver acknowledges cumulatively: `ack_num` is the next number it expects, so it implicitly says "I have everything before this." On top of that, every acknowledgment includes `recv_window` — how many more segments it can accept right now, based on how much free space it has in its buffer. The sender never sends beyond this window. This is what keeps the receiver from being overwhelmed.

## The sending side

`init_sender` receives the link's bandwidth and latency, and from these I compute a window starting from the BDP (how much fits on the wire at any given moment), with a minimum floor so that on fast links I fill the pipe completely. The window I actually send with is the minimum of my own window and what the receiver reports it can still accept.

`send_data` never blocks. When the application hands me data, I copy it into an internal buffer and return how many bytes I took; if the buffer is full, I return `-1` and the application tries again. Once I have the data, I cut segments out of the buffer and put them on the wire as long as the window has room. This way the application can hand me an entire file quickly, and the real output rate is dictated by the window — the application never has to wait between calls. Without this internal buffer, when the window filled up `send_data` accepted only part of the data, the client fell into a long sleep after each chunk, the transfer became extremely slow, and the tests failed.

I detect losses in two ways. Each connection has its own timer: if no forward progress in the acknowledgments has arrived since the last tick, I retransmit the entire unacknowledged window. In addition, I count duplicate acknowledgments, and when I catch three identical ones in a row, I immediately retransmit the segment at the head of the window without waiting for the timer. This greatly shortens recovery on large files, where I would otherwise lose about a hundred milliseconds per dropped packet. When an acknowledgment that actually advances arrives, I remove the acknowledged data from the window, update the window advertised by the receiver, and immediately push out whatever else fits, keeping the pipe full.

## Receiving data

`init_receiver` sets the buffer size. `recv_data` blocks on a condition variable until there is something deliverable in order, copies it into the application's buffer, and — because it has just freed up space — sends an acknowledgment carrying the new window, so the sender knows it can resume if it had stopped.

On the handling thread I process segments selectively. If the exact sequence number I'm expecting arrives, I deliver it and immediately check whether I also have the following ones stored, so I can hand them all over in order. Segments already received are ignored. After each segment I send an acknowledgment with the current window. If the thread times out without receiving anything, I resend the last acknowledgment, so I don't stay blocked because of a window update that was lost along the way.

## Multiple connections at once

I keep separate state for each connection, indexed by `conn_id`. The server has one listening socket and one data socket per client, and `wait4connect` can be called multiple times to accept new clients. The handling threads watch all active sockets and all timers at once with `poll`, routing each event to the connection it belongs to.

## Synchronization

Each connection has its own mutex, which protects the state shared between the application thread and the handling thread. Delivery to `recv_data` is signaled through a condition variable every time something has been delivered in order. One detail I had to fix: while no connection exists yet, the handling thread periodically yields the CPU instead of occupying it needlessly — otherwise, on a single-core machine, it blocked connection establishment.
