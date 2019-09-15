#![cfg_attr(feature = "unstable", feature(fused))]

extern crate bcc;
extern crate byteorder;
extern crate clap;
extern crate colored;
extern crate failure;
extern crate hpack;

mod bpf;
mod h2;
mod output;

use clap::{App, Arg};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;

fn main() {
    let matches = App::new("SPF")
        .version("0.1")
        .arg(
            Arg::with_name("filter")
                .short("f")
                .long("filter")
                .help("Prefix of unix sockets to filter on")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .help("Output format (default, h2)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("bpf_debug")
            .long("bpf-debug")
            .help("Output extra information about why calls are not traced. *NOTE*: This may increase the number of dropped packets.")
        )
        .get_matches();

    let formatter = match matches.value_of("output").unwrap_or("default") {
        "h2" => h2::format,
        "default" => bpf::stdout_output,
        _ => panic!("invalid format"),
    };

    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    let (sender, _receiver) = mpsc::channel();

    let (format_sender, format_handle) = output::new_output_thread(formatter);
    if let Err(x) = bpf::do_main(
        matches.value_of("filter").map(str::to_string),
        matches.value_of("bpf_debug").map(|_| true).unwrap_or(false),
        runnable,
        format_sender,
        sender,
    ) {
        eprintln!("Error: {}", x);
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }

    format_handle.join().unwrap();
}
