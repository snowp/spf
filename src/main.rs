#![cfg_attr(feature = "unstable", feature(fused))]

extern crate bcc;
extern crate byteorder;
extern crate clap;
extern crate colored;
extern crate failure;
extern crate hpack;

mod bpf;
mod h2;

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
                .help("Output format (default, pcap)")
                .takes_value(true),
        )
        .get_matches();

    let formatter = if matches.value_of("output").unwrap_or("default") == "default" {
        bpf::stdout_output
    } else {
        h2::format
    };

    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    let (sender, _receiver) = mpsc::channel();
    if let Err(x) = bpf::do_main(
        matches.value_of("filter").map(str::to_string),
        runnable,
        formatter,
        sender,
    ) {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
    }
}
