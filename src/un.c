#include <linux/socket.h>
#include <linux/net.h>
#include <linux/un.h>
#include <linux/uio.h>
#include <net/af_unix.h>

#define BUFFER_SIZE 108
#define READ_BUFFER_SIZE 256
#define MAX_BUFFER_SIZE 1024
#define MAX_CHUNKS ((unsigned)16)

#ifdef UN_FILTER
// Returns true if the path of addr matches the prefix given in UN_FILTER.
inline static bool cmp_un_path(struct unix_address *addr)
{
  const char str[] = UN_FILTER;
  size_t len = sizeof(str) - 1; // ignore null char

  // No address, can't be equal.
  if (addr == NULL)
  {
    return false;
  }

  // If both are empty they're equal.
  if (len == 0 && addr->len == 0)
  {
    return true;
  }

  // If the prefix is longer than the addr, give up early.
  if (len > addr->len)
  {
    return false;
  }

  // This ensures we don't go out of bounds on the next check.
  if (len == 0 || addr->len == 0)
  {
    return false;
  }

  // Adjust prefix character for abstract unix sockets.
  size_t start_index = 0;
  if (addr->name->sun_path[0] == '\0' && str[0] == '@')
  {
    start_index = 1;
  }

  // Read out all the data we care about.
  // For some reason accessing the data directly without a bpf_probe_read doesn't seem to work.
  char copy[sizeof(str)];
  bpf_probe_read(&copy, sizeof(str), addr->name->sun_path);

#pragma unroll
  for (size_t i = 0; i < len; ++i)
  {
    if (i < start_index)
    {
      continue;
    }

    if (str[i] != copy[i])
    {
      return false;
    }
  }

  return true;
}
#endif

#ifdef UN_FILTER
#define FILTER(addr)      \
  if (!cmp_un_path(addr)) \
  {                       \
    return;               \
  }
#define FILTER_RET(addr, retval) \
  if (!cmp_un_path(addr))        \
  {                              \
    return retval;               \
  }
#else
#define FILTER(addr) \
  {                  \
  }
#define FILTER_RET(addr, retval) \
  {                              \
  }
#endif

// Allows us to communicate why a unix_stream_sendmsg did not result in a data entry.
enum status_t
{
  OK,
  NO_PATH,
  NO_DATA,
  NOT_AF_UNIX
};

struct send_data_t
{
  u32 pid;
  u32 peer_pid;
  u64 msg_size;
  u64 pipe_type;
  u8 truncated;
  char buffer[READ_BUFFER_SIZE];
  char sun_path[64];
  u8 path_len;
  u64 time_ns;
  // Whether this is sent to the bound side of the unix socket (i.e. the "server" side).
  u8 bound;
  u8 status;
};

BPF_PERF_OUTPUT(data_events);

inline static size_t copy_iov(struct msghdr *hdr, char *buffer, u8 volatile *truncated)
{
  struct msghdr stack_hdr;
  bpf_probe_read(&stack_hdr, sizeof(stack_hdr), hdr);

  struct iovec vec;
  bpf_probe_read(&vec, sizeof(vec), stack_hdr.msg_iter.iov);

  // We assume that 1) there is only one iov chunk and 2) that the union is of type ITER_IOVEC.
  size_t to_copy = vec.iov_len;
  if (to_copy > READ_BUFFER_SIZE)
  {
    *truncated = 1;
    to_copy = READ_BUFFER_SIZE;
  }

  bpf_probe_read(buffer, to_copy, vec.iov_base);

  return to_copy;
}

inline static size_t copy_sun_path(struct unix_sock *us, struct send_data_t *data)
{
  struct unix_address *addr = us->addr;

  if (addr->len)
  {
    FILTER_RET(addr, 0)
    size_t l = addr->len;
    if (l > 64)
    {
      l = 64;
    }
    bpf_probe_read(data->sun_path, l, addr->name->sun_path);
    data->path_len = l;

    return l;
  }

  return 0;
}

inline static void submit(struct pt_regs *ctx, struct send_data_t *data)
{
#ifndef DEBUG_BPF
  if (data->status != OK)
  {
    return;
  }
#endif

  data_events.perf_submit(ctx, data, sizeof(struct send_data_t));
}

inline static void copy_stream_data(struct pt_regs *ctx, struct socket *socket, struct msghdr *hdr)
{
  struct send_data_t data = {};
  unsigned char truncated = 0;

  size_t pid_tgid = bpf_get_current_pid_tgid();
  data.pid = (u32)(pid_tgid >> 32);
  data.time_ns = bpf_ktime_get_ns();

  // Homemade ASSERT: copy_iov assumes that the size of the buffer is READ_BUFFER_SIZE. The for
  // loop is optimized out so as long as the condition is true the program will be valid.
  if (sizeof(data.buffer) != sizeof(char) * READ_BUFFER_SIZE)
  {
    for (;;)
    {
    }
  }

  if (socket->type != AF_UNIX)
  {
    data.status = NOT_AF_UNIX;
    submit(ctx, &data);
    return;
  }

  struct sock *sock = socket->sk;
  struct unix_sock *us = unix_sk(sock);
  struct pid *peer_pid = socket->sk->sk_peer_pid;
  if (peer_pid)
  {
    data.peer_pid = peer_pid->numbers[0].nr;
  }

  struct sock *peer = us->peer;
  if (peer->sk_family != AF_UNIX)
  {
    data.status = NOT_AF_UNIX;
    submit(ctx, &data);
    return;
  }

  if (!copy_sun_path(us, &data))
  {
    if (!copy_sun_path(unix_sk(peer), &data))
    {
      data.status = NO_PATH;
      submit(ctx, &data);
      return;
    }
  }
  else
  {
    data.bound = 1;
  }

  data.msg_size = copy_iov(hdr, data.buffer, &data.truncated);
  data.pipe_type = hdr->msg_iter.type;

  if (data.msg_size)
  {
    submit(ctx, &data);
  }
  else
  {
    data.status = NO_DATA;
  }
}

int un_stream_send_entry(struct pt_regs *ctx, struct socket *socket, struct msghdr *hdr, size_t s)
{
  copy_stream_data(ctx, socket, hdr);
  return 0;
}