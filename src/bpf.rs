use bcc::core::BPF;
use bcc::perf::init_perf_map;
use colored::*;
use failure::Error;
use std::collections::HashMap;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::sync::Arc;

pub fn stdout_output(data: &send_data_t) {
    let formatter = |data: &send_data_t| -> String {
        fixed_length_string(&data.buffer, data.msg_size as usize)
    };

    let truncated_str = if data.truncated != 0 {
        " (truncated)".to_string().red()
    } else {
        "".to_string().blue()
    };

    println!(
        "{} {} {} {}",
        format!("[{}\t-> {}]", data.pid, data.peer_pid).yellow(),
        socket_name(&data.sun_path, Some(data.path_size as usize)).green(),
        formatter(&data),
        format!("[{} bytes{}]", data.msg_size, truncated_str).blue(),
    );
}

pub fn do_main<F>(
    path_filter: Option<String>,
    debug: bool,
    runnable: Arc<AtomicBool>,
    f: F,
    started: Sender<()>,
) -> Result<(), Error>
where
    F: Fn(&send_data_t),
{
    let mut defines = match path_filter {
        Some(path) => format!("#define UN_FILTER \"{}\"\n", path),
        _ => "".to_string(),
    };
    if debug {
        defines += "#define DEBUG_BPF\n";
    }

    let code = include_str!("un.c");
    let mut module = BPF::new(&(defines + code))?;

    let (sender, receiver) = mpsc::channel();
    let data_table = module.table("data_events");
    let mut data_perf_map = init_perf_map(data_table, move || {
        let sender_clone = sender.clone();
        Box::new(move |x| {
            let data: send_data_t = parse_struct(x);
            sender_clone.send(data.clone()).unwrap();
        })
    })?;

    {
        let entry_probe = module.load_kprobe("un_stream_send_entry")?;
        module.attach_kprobe("unix_stream_sendmsg", entry_probe)?;
    }

    let mut failures: HashMap<SendStatus, u64> = HashMap::new();
    started.send(()).unwrap();
    while runnable.load(Ordering::SeqCst) {
        data_perf_map.poll(200);
        // Drain the received updates and invoke the output function with each value.
        while match receiver.try_recv() {
            Ok(data) => {
                if let Some(status) = SendStatus::from_u8(data.status) {
                    if status == SendStatus::Ok {
                        f(&data)
                    }
                    let count = *failures.get(&status).unwrap_or(&0);
                    failures.insert(status, count + 1);
                }
                true
            }
            Err(_) => false,
        } {}
    }

    if !failures.is_empty() {
        eprintln!("{:?}", failures);
    }

    Result::Ok(())
}

fn fixed_length_string(x: &[u8], size: usize) -> String {
    x[0..size]
        .iter()
        .map(|b| {
            let vec: Vec<u8> = std::ascii::escape_default(*b).collect();
            String::from_utf8(vec).unwrap()
        })
        .collect()
}

fn socket_name(x: &[u8], len: Option<usize>) -> String {
    let mut iter = match len {
        Some(l) => x[0..l].iter(),
        _ => x.iter(),
    };
    match iter.position(|&r| r == 0) {
        // Handle abstract sockets.
        Some(0) => "@".to_string() + &socket_name(&x[1..], len.map(|l| l - 1)),
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct send_data_t {
    pub pid: u32,
    pub peer_pid: u32,
    pub msg_size: u64,
    pub pipe_type: u64,
    pub truncated: u8,
    pub buffer: [u8; 200],
    pub sun_path: [u8; 64],
    pub path_size: u8,
    pub time_ns: u64,
    pub bound: u8,
    pub status: u8,
}

#[derive(Debug, Hash, Eq, PartialEq)]
enum SendStatus {
    Ok,
    NoPath,
    NoData,
    NotAfUnix,
}

impl SendStatus {
    fn from_u8(d: u8) -> Option<Self> {
        match d {
            0x0 => Some(SendStatus::Ok),
            0x1 => Some(SendStatus::NoPath),
            0x2 => Some(SendStatus::NoData),
            0x3 => Some(SendStatus::NotAfUnix),
            _ => None,
        }
    }
}

fn parse_struct<T>(x: &[u8]) -> T {
    unsafe { ptr::read(x.as_ptr() as *const T) }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::io;
    use std::io::Read;
    use std::io::{ErrorKind, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::mpsc::Receiver;
    use std::sync::Arc;
    use std::thread;
    use std::time;

    fn read_first_ack(s: &mut UnixStream) {
        let mut buf = [0; 32];

        if let Err(e) = s.read(&mut buf) {
            panic!(e);
        }
    }

    fn read_nth_ack(s: &mut UnixStream, i: usize) {
        let ack_str = format!("acking {}", i);
        let mut buf = [0; 32];

        s.set_nonblocking(true).unwrap();
        loop {
            if let Ok(d) = s.read(&mut buf) {
                if d == 0 {
                    thread::sleep(time::Duration::from_millis(10));
                }
                if d == ack_str.len() {
                    break;
                } else {
                    panic!("unexpected payload {}", String::from_utf8_lossy(&buf[0..d]));
                }
            }
        }

        s.set_nonblocking(false).unwrap();
    }

    // Sets up a handler for a unix socket and listens on the provided path.
    // To facilitate testing, the handler does the following:
    //   - Upon accepting a new connection, the handler waits for data to be
    //     written that contains a string number that is used to inform it how
    //     many more packets will be written to the stream.
    //   - The handler acks the count by responding with "ack"
    //   - The handler acks each subsequent message by writing "acking {}" with
    //     a number indicating which write is being acked.
    fn un_listen_and_accept(
        path: String,
        runnable: Arc<AtomicBool>,
    ) -> io::Result<thread::JoinHandle<()>> {
        fs::remove_file(&path).unwrap_or_default();
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;

        Ok(thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        thread::spawn(move || {
                            let mut first_read = false;
                            let mut expected_writes = 0;
                            let mut buf: [u8; 256] = [0; 256];
                            loop {
                                let r = stream.read(&mut buf);
                                match r {
                                    Ok(0) => {}
                                    Ok(d) => {
                                        // First read tells us how many to expect.
                                        if !first_read {
                                            expected_writes = String::from_utf8_lossy(&buf[0..d])
                                                .parse::<u32>()
                                                .unwrap();
                                            first_read = true;
                                            stream.write(b"ack").unwrap();
                                        } else {
                                            // Afterwards we ack each message.
                                            stream
                                                .write(
                                                    format!("acking {}", expected_writes)
                                                        .as_bytes(),
                                                )
                                                .unwrap();
                                            expected_writes -= 1;
                                        }

                                        // And close the pipe once we've received all our writes.
                                        if first_read && expected_writes == 0 {
                                            return;
                                        }
                                    }
                                    _ => return,
                                };
                            }
                        });
                    }
                    Err(e) => {
                        if e.kind() != ErrorKind::WouldBlock {
                            eprintln!("error while accepting new stream {}", e);
                        }
                        thread::sleep(time::Duration::from_millis(100));
                    }
                }

                if !runnable.load(Ordering::SeqCst) {
                    return;
                }
            }
        }))
    }

    fn verify_update(receiver: &Receiver<super::send_data_t>, sun_path: &str, payload: &str) {
        let update = receiver.recv().unwrap();
        assert_eq!(
            super::socket_name(&update.sun_path, Some(update.path_size as usize)),
            sun_path
        );
        assert_eq!(
            super::fixed_length_string(&update.buffer, update.msg_size as usize),
            payload
        );
    }

    #[test]
    // #[cfg(feature = "with_root")]
    fn test_do_main() {
        eprintln!("doing test");
        let b = AtomicBool::new(true);
        let barc = Arc::new(b);

        let mut join_handles = Vec::new();

        join_handles.push({
            let barc_clone = barc.clone();
            match un_listen_and_accept("/tmp/spf2.test".to_string(), barc_clone) {
                Ok(h) => h,
                Err(e) => panic!("failed to listen on spf2 socket {}", e),
            }
        });

        join_handles.push({
            let barc_clone = barc.clone();
            match un_listen_and_accept("/tmp/spf.test".to_string(), barc_clone) {
                Ok(h) => h,
                Err(e) => panic!("failed to listen on spf socket {}", e),
            }
        });

        let (sender, receiver) = mpsc::channel();

        let (started_sender, started_receiver) = mpsc::channel();
        let barc_clone = barc.clone();
        thread::spawn(move || {
            super::do_main(
                Some("/tmp/spf.test".to_string()),
                true,
                barc_clone,
                move |data| sender.send(data.clone()).unwrap(),
                started_sender,
            )
            .unwrap();
        });

        started_receiver.recv().unwrap();

        let mut stream = UnixStream::connect("/tmp/spf.test").unwrap();
        stream.write(b"1").unwrap();
        read_first_ack(&mut stream);

        stream.write(b"hello").unwrap();
        read_nth_ack(&mut stream, 1);

        // We should get one update with the window.
        verify_update(&receiver, "/tmp/spf.test", "1");
        // Followed by the initial ack.
        verify_update(&receiver, "/tmp/spf.test", "ack");
        // Then another string is sent.
        verify_update(&receiver, "/tmp/spf.test", "hello");
        // And the server responds.
        verify_update(&receiver, "/tmp/spf.test", "acking 1");

        // Writing to the other socket should not trigger an event
        let mut stream = UnixStream::connect("/tmp/spf2.test").unwrap();

        stream.write(b"0").unwrap();
        read_first_ack(&mut stream);

        assert!(receiver
            .recv_timeout(time::Duration::from_millis(150))
            .is_err());

        // A more complicated test: start a connection and send 10 messages
        // in a row without reading off the socket, then read all 10 acks.
        let mut stream = UnixStream::connect("/tmp/spf.test").unwrap();
        stream.write(b"9").unwrap();
        read_first_ack(&mut stream);

        // Make 9 to the filtered unix socket and write/read from it.
        for _ in 0..9 {
            stream.write(b"xxxx").unwrap();
        }

        for i in 9..0 {
            read_nth_ack(&mut stream, i);
        }

        // We should end up with 100 events of each
        let mut updates = HashMap::new();
        for _ in 0..20 {
            let size = receiver
                .recv_timeout(time::Duration::from_millis(100))
                .unwrap()
                .msg_size;
            let current_count = updates.get(&size).unwrap_or(&0).clone();
            updates.insert(size.clone(), current_count + 1);
        }

        // Instead of bothering with checking all the strings we just verify that the length of each
        // update makes sense with what we sent.

        assert_eq!(updates.len(), 4);

        // 1 packet with size 3 (ack)
        assert_eq!(updates.get(&3), Some(&1));
        // 9 packets with size 4 (xxxx)
        assert_eq!(updates.get(&4), Some(&9));
        // 1 packet with size 1 (9)
        assert_eq!(updates.get(&1), Some(&1));
        // 9 packets with size 8 (acking X)
        assert_eq!(updates.get(&8), Some(&9));

        barc.store(false, Ordering::SeqCst);

        // Ensure that we're properly closing out the listen threads.
        for h in join_handles {
            h.join().unwrap();
        }
    }

}
