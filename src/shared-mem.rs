// Starter code for ECE 459 Lab 2, Winter 2021

// YOU SHOULD MODIFY THIS FILE TO USE THREADING AND SHARED MEMORY

#![warn(clippy::all)]
use futures::executor::block_on;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use tokio::sync::{Semaphore, SemaphorePermit};
use std::env;
use std::clone::Clone;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use crossbeam::utils::Backoff;
use std::thread::JoinHandle;
use std::ops::Deref;

const DEFAULT_ALPHABETS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;

// Check if a JWT secret is correct
fn is_secret_valid(message: &[u8], signature: &[u8], secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.update(message);
    mac.verify(signature).is_ok()
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
        let permit = self.acquire_semaphore(&self.spaces);
        {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.push_back(x);
        }
        self.items.add_permits(1);
        permit.forget();
    }

    fn acquire_semaphore<'a>(&'a self, sem: &'a Semaphore) -> SemaphorePermit<'a> {
        // return block_on(sem.acquire());
        let backoff = Backoff::new();
        loop {
            if backoff.is_completed() {
                return block_on(sem.acquire());
            }
            let res = sem.try_acquire();
            match res {
                Ok(permit) => return permit,
                Err(_) => backoff.spin()
            }
        }
    }

    fn pop(&self) -> Option<Vec<u8>> {
        let permit = self.acquire_semaphore(&self.items);
        let x = {
            let mut buffer = self.buffer.lock().unwrap();
            buffer.pop_front().unwrap()
        };
        self.spaces.add_permits(1);
        permit.forget();
        return x;
    }
}

fn generate_secrets(alphabet: &[u8],
                    max_len: usize,
                    buffer: &SharedBuffer,
                    is_answer_found: &Arc<AtomicBool>) {
    let mut frontier = vec![Vec::<u8>::new()];
    while frontier.len() > 0 {
        let secret = frontier.pop().unwrap();
        if is_answer_found.load(Ordering::SeqCst) {
            return;
        }
        buffer.push(Some(secret.clone()));
        if secret.len() < max_len {
            for c in alphabet {
                let mut next_sec = secret.clone();
                next_sec.push(*c);
                frontier.push(next_sec);
            }
        }
    }
}

fn start_consumers(num_workers: usize,
                   shared_buffer: &SharedBuffer,
                   is_answer_found: &Arc<AtomicBool>,
                   answer: &Arc<Mutex<Option<String>>>,
                   message: &Arc<Vec<u8>>,
                   signature: &Arc<Vec<u8>>) -> Vec<JoinHandle<()>> {
    let mut workers = vec![];
    for _ in 0..num_workers {
        let message = message.clone();
        let signature = signature.clone();
        let shared_buffer = shared_buffer.clone();
        let answer = answer.clone();
        let is_answer_found = is_answer_found.clone();
        workers.push(thread::spawn(move || {
            loop {
                let secret = match shared_buffer.pop() {
                    Some(sec) => sec,
                    None => return
                };
                if is_secret_valid(&message, &signature, &secret) {
                    let s = std::str::from_utf8(&secret).unwrap().to_string();
                    {
                        *answer.lock().unwrap() = Some(s);
                    }
                    is_answer_found.store(true, Ordering::SeqCst);
                    return;
                }
            }
        }));
    }
    return workers;
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
    let message = Arc::new(token.as_bytes()[..dot].to_vec());
    // signaturenature is everything after the last dot
    let signature = &token.as_bytes()[dot + 1..];
    // convert base64 encoding into binary
    let signature = match base64::decode_config(signature, base64::URL_SAFE_NO_PAD) {
        Ok(signature) => Arc::new(signature),
        Err(_) => {
            eprintln!("Invalid signaturenature");
            return;
        }
    };

    let num_workers = num_cpus::get();
    let buffer_capacity = num_workers * 8;
    let shared_buffer = SharedBuffer::new(buffer_capacity);
    let is_answer_found = Arc::new(AtomicBool::new(false));
    let answer = Arc::new(Mutex::<Option<String>>::new(None));

    let workers = start_consumers(num_workers, &shared_buffer, &is_answer_found, &answer, &message, &signature);
    generate_secrets(&alphabet, max_len as usize, &shared_buffer, &is_answer_found);

    for _ in 0..num_workers {
        shared_buffer.push(None);
    }
    for w in workers {
        w.join().unwrap();
    }

    {
        match answer.lock().unwrap().deref() {
            Some(answer) => println!("{}", answer),
            None => println!("No answer found")
        };
    }
}
