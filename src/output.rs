use super::bpf;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;
use std::thread::JoinHandle;

pub fn new_output_thread<F>(f: F) -> (Sender<bpf::send_data_t>, JoinHandle<()>)
where
    F: Fn(&bpf::send_data_t) + Send + Sync + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let handle = thread::spawn(move || loop {
        match receiver.recv() {
            Ok(d) => f(&d),
            Err(_) => return,
        }
    });

    (sender, handle)
}
