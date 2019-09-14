extern crate base64;
extern crate bcc;
extern crate colored;
extern crate failure;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use colored::*;
use failure::Error;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::env;

fn do_main(path_filter: Option<String>, runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let defines = match path_filter {
        Some(path) => format!("#define UN_FILTER \"{}\"\n", path),
        _ => "".to_string(),
    };
    let code = include_str!("un.c");
    let mut module = BPF::new(&(defines + code))?;

    let data_table = module.table("data_events");
    let mut data_perf_map = init_perf_map(data_table, || {
        Box::new(|x| {
            let formatter = |data: &send_data_t| -> String {
                fixed_length_string(&data.buffer, data.msg_size as usize)
            };
            let data: send_data_t = parse_struct(x);
            println!(
                "{} {} {} {} {} {}",
                format!("[{} -> {}]", data.pid, data.peer_pid).yellow(),
                socket_name(&data.sun_path, Some(data.path_size as usize)).green(),
                format!("[{} bytes]", data.path_size).green(),
                formatter(&data),
                format!("[{} bytes]", data.msg_size).blue(),
                if data.truncated != 0 {
                    "[truncated]".to_string().red()
                } else {
                    "".to_string().blue()
                },
            );
        })
    })?;

    {
        let entry_probe = module.load_kprobe("un_stream_send_entry")?;
        module.attach_kprobe("unix_stream_sendmsg", entry_probe)?;
    }

    while runnable.load(Ordering::SeqCst) {
        data_perf_map.poll(200);
    }

    Result::Ok(())
}

fn fixed_length_string(x: &[u8], size: usize) -> String {
    x[0..size]
        .iter()
        .map(|b| {
            let c = *b as char;
            if c.is_ascii() && !c.is_ascii_control() {
                format!("{}", c)
            } else if *b < 0x10 {
                format!("\\0{:x}", b)
            } else {
                format!("\\{:x}", b)
            }
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
        Some(0) => "@".to_string() + &socket_name(&x[1..], None),
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

#[repr(C)]
struct send_data_t {
    pid: u32,
    peer_pid: u32,
    msg_size: u64,
    pipe_type: u64,
    truncated: u8,
    buffer: [u8; 256],
    sun_path: [u8; 64],
    path_size: u8,
}

fn parse_struct<T>(x: &[u8]) -> T {
    unsafe { ptr::read(x.as_ptr() as *const T) }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(env::args().nth(1), runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
