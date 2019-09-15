# spf (unix socket sniffer + HTTP/2 protocol parser)

spf is a eBPF based tool that facilitates tracing of data that is written to unix sockets.
It allows specifying the name of the unix socket to watch and can output data either as
raw escaped frames or as decoded HTTP/2 frames.

## Limitations
The eBPF tracer will only read the first 10 iovec in the msghdr passed to `unix_stream_sendmsg`,
which means that some data will not be picked up when the kernel passes mulitple buffers to `unix_stream_sendmsg`.

The buffers are passed back to userspace on each CPU and written to stdout serially: the order of
frames are not guaranteed to match the actual order in which data was sent. An attempt to sort the
incoming events is made: we wait 100ms after each event for newer events (according to kernel time) arrives.

To work within the limitations of eBPF programs, limits on how much data can be emitted to userspace exists. Namely:
- the length of the `sun_path` copied to userspace is 64 bytes
- the max length of the buffer copied to userspace per iovec is 200 bytes
- the max number of iovecs that generate an event per msghdr is 10

These limits are in place due to 1) the stack size limit of eBPF programs and 2) the program size limit.

## Etc.
The eBPF code is inspired by https://github.com/nccgroup/ebpf/tree/master/unixdump, while the userland code is completely new.

The HTTP/2 parser is tested against the corpus files in the nghttp2 repo, which again are sampled from http2-spec.

This was tested on Linux 4.15 with fix/oh-my PR applied to rust-bcc.
