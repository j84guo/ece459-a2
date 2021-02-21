// Starter code for ECE 459 Lab 2, Winter 2021

// YOU SHOULD MODIFY THIS FILE TO USE THREADING AND SHARED MEMORY

#![warn(clippy::all)]
use futures::executor::block_on;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use tokio::sync::Semaphore;
use std::env;
use std::clone::Clone;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

const DEFAULT_ALPHABETS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;

// Check if a JWT secret is correct
fn is_secret_valid(msg: &[u8], sig: &[u8], secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.update(msg);
    mac.verify(sig).is_ok()
}

#[derive(Clone)]
struct SharedBuffer {
    buffer: Arc<Mutex<VecDeque<Option<Vec<u8>>>>>,
    items: Arc<Semaphore>,
    spaces: Arc<Semaphore>
}

impl SharedBuffer {
    fn new(capacity: usize) -> SharedBuffer {
        return SharedBuffer {
            buffer: Arc::new(Mutex::new(VecDeque::<Option<Vec<u8>>>::with_capacity(capacity))),
            items: Arc::new(Semaphore::new(0)),
            spaces: Arc::new(Semaphore::new(capacity))
        };
    }

    fn push(&self, x: Option<Vec<u8>>) {
        let permit = block_on(self.spaces.acquire());
        {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.push_back(x);
        }
        self.items.add_permits(1);
        permit.forget();
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let permit = block_on(self.items.acquire());
        let x = {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.pop_front().unwrap()
        };
        self.spaces.add_permits(1);
        permit.forget();
        return x;
    }
}

fn generate_secrets(sec: Vec<u8>,
                    alphabet: &[u8],
                    max_len: usize,
                    buffer: &SharedBuffer,
                    done_flag: &Arc<AtomicBool>) {
    if done_flag.load(Ordering::SeqCst) {
        return;
    }
    buffer.push(Some(sec.clone()));
    if sec.len() == max_len {
        return;
    }
    for &c in alphabet {
        let mut next_sec: Vec<u8> = Vec::with_capacity(sec.len() + 1);
        next_sec.extend(sec.iter());
        next_sec.push(c);
        generate_secrets(next_sec, alphabet, max_len, buffer, done_flag);
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() < 3 {
        eprintln!("Usage: <token> <max_len> [alphabet]");
        return;
    }

    let token = &args[1];

    let max_len = match args[2].parse::<u32>() {
        Ok(len) => len,
        Err(_) => {
            eprintln!("Invalid max length");
            return;
        }
    };

    let alphabet: Vec<u8> = args
        .get(3)
        .map(|a| a.as_bytes())
        .unwrap_or(DEFAULT_ALPHABETS)
        .into();

    // find index of last '.'
    let dot = match token.rfind('.') {
        Some(pos) => pos,
        None => {
            eprintln!("No dot found in token");
            return;
        }
    };

    // message is everything before the last dot
    let msg = token.as_bytes()[..dot].to_vec();
    // signature is everything after the last dot
    let sig = &token.as_bytes()[dot + 1..];

    // convert base64 encoding into binary
    let sig = match base64::decode_config(sig, base64::URL_SAFE_NO_PAD) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("Invalid signature");
            return;
        }
    };

    let num_workers = num_cpus::get();
    let buffer_capacity = num_workers * 8;
    let buffer = SharedBuffer::new(buffer_capacity);
    let done_flag = Arc::new(AtomicBool::new(false));

    let mut workers = vec![];
    for _ in 0..num_workers {
        let msg = msg.clone();
        let sig = sig.clone();
        let buffer = buffer.clone();
        let done_flag = done_flag.clone();
        workers.push(thread::spawn(move || {
            loop {
                let sec = match buffer.pop() {
                    Some(sec) => sec,
                    None => return
                };
                if is_secret_valid(&msg, &sig, &sec) {
                    println!("{}", std::str::from_utf8(&sec).unwrap());
                    done_flag.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }));
    }

    generate_secrets(Vec::<u8>::new(), &alphabet, max_len as usize, &buffer, &done_flag);

    for _ in 0..num_workers {
        buffer.push(None);
    }
    for w in workers {
        w.join().unwrap();
    }
}
