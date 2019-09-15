# spf (unix socket sniffer + HTTP/2 protocol parser)

spf is a eBPF based tool that facilitates tracing of data that is written to unix sockets.
It allows specifying the name of the unix socket to watch and can output data either as
raw escaped frames or as decoded HTTP/2 frames.

## Limitations
The eBPF tracer will only read the first 10 iovec in the msghdr passed to `unix_stream_sendmsg`,
which means that some data will not be picked up when the kernel passes mulitple buffers to `unix_stream_sendmsg`.

The buffers are passed back to userspace and written to stdout serially: the order of frames are not guaranteed to match
the actual order in which data was sent. This may result in HTTP/2 frames being displayed out of order.

## TODOs
* To fix the ordering issue we'll likely need to sort the events in userspace based on kernel time. This also means that events
  need to be batched for some period instead of outputted immediately. For example, a set of moving windows could be used to allow
  each event to wait for some time for new frames:

```
  A                    B       C
  |--------------------|-------|
  |            sort            |
  |        output      |
```

  All events in the sort window are sorted, then all events that fall into the output window are outputted. This allows the events
  between B and C to be compared with future events once we get more events or the window times out.

  For example: an event comes in at t0=0 (this is A), so we wait for t=200ms (this is C) and sort all events that fit within that window.
  We then look at the first event in this sorted list. The time at which this event happened in kernel time is t0'. We then output all events
  that fit into t0' + 150ms. Any event that happened after t0' + 150ms will be left for a future sort window. The new t0 is the first event after
  t0' + 150ms.

  t0' != t0 after each sort as the first event that triggered the window might not have been the first event according to kernel time.

## Etc.
The eBPF code is inspired by https://github.com/nccgroup/ebpf/tree/master/unixdump, while the userland code is completely new.

The HTTP/2 parser is tested against the corpus files in the nghttp2 repo, which again are sampled from http2-spec.

This was tested on Linux 4.15 with fix/oh-my PR applied to rust-bcc.
