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
    pub buffer: [u8; 256],
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
    use std::fs;
    use std::io;
    use std::io::{ErrorKind, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time;

    fn un_listen_and_accept(path: String, runnable: Arc<AtomicBool>) -> io::Result<()> {
        fs::remove_file(&path).unwrap_or_default();
        eprintln!("binding");
        let listener = UnixListener::bind(path)?;
        eprintln!("bound");
        listener.set_nonblocking(true)?;

        eprintln!("spawning");
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        stream.write(b"hello from server").unwrap();
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
        });

        Ok(())
    }

    #[test]
    // #[cfg(feature = "with_root")]
    fn test_do_main() {
        eprintln!("doing test");
        let b = AtomicBool::new(true);
        let barc = Arc::new(b);

        {
            println!("starting one");
            let barc_clone = barc.clone();
            match un_listen_and_accept("/tmp/spf2.test".to_string(), barc_clone) {
                Err(e) => eprintln!("failed to listen on spf2 socket {}", e),
                _ => {}
            }
            println!("started one");
        }

        {
            let barc_clone = barc.clone();
            match un_listen_and_accept("/tmp/spf.test".to_string(), barc_clone) {
                Err(e) => eprintln!("failed to listen on spf socket {}", e),
                _ => {}
            }
        }

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
        stream.write(b"hello").unwrap();

        // The first event should be the data written by the client.
        {
            let update = receiver.recv().unwrap();
            assert_eq!(
                super::socket_name(&update.sun_path, Some(update.path_size as usize)),
                "/tmp/spf.test"
            );
            assert_eq!(
                super::fixed_length_string(&update.buffer, update.msg_size as usize),
                "hello"
            );
        }

        // Second event should be the server responding.
        {
            let update = receiver.recv().unwrap();
            assert_eq!(
                super::socket_name(&update.sun_path, Some(update.path_size as usize)),
                "/tmp/spf.test"
            );
            assert_eq!(
                super::fixed_length_string(&update.buffer, update.msg_size as usize),
                "hello from server"
            );
        }

        // Writing to the other socket should not trigger an event
        let mut stream = UnixStream::connect("/tmp/spf2.test").unwrap();
        stream.write(b"hello").unwrap();

        assert!(receiver
            .recv_timeout(time::Duration::from_millis(150))
            .is_err());

        barc.store(false, Ordering::SeqCst);
    }

}
