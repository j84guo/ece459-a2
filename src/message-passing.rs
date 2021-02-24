// Starter code for ECE 459 Lab 2, Winter 2021

// YOU SHOULD MODIFY THIS FILE TO USE THEADING AND MESSAGE-PASSING

#![warn(clippy::all)]
use crossbeam::channel::{bounded, Receiver, Sender};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::env;
use std::thread;
use std::thread::JoinHandle;
use std::sync::Arc;

const DEFAULT_ALPHABETS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;

// Check if a JWT secret is correct
fn is_secret_valid(message: &[u8],
                   signature: &[u8],
                   secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.update(message);
    mac.verify(signature).is_ok()
}

fn generate_secrets(alphabet: &[u8],
                    max_len: usize,
                    sec_send_end: &Sender<Option<Vec<Vec<u8>>>>,
                    res_recv_end: &Receiver<Vec<u8>>) {
    let mut frontier = vec![Vec::<u8>::new()];
    let mut batch = Vec::<Vec<u8>>::new();
    const BATCH_SIZE: usize = 1 << 5;
    while frontier.len() > 0 {
        let secret = frontier.pop().unwrap();
        if !res_recv_end.is_empty() {
            return;
        }
        batch.push(secret.clone());
        if batch.len() == BATCH_SIZE {
            sec_send_end.send(Some(batch)).unwrap();
            batch = Vec::<Vec<u8>>::new();
        }
        if secret.len() < max_len {
            for c in alphabet {
                let mut next_sec = secret.clone();
                next_sec.push(*c);
                frontier.push(next_sec);
            }
        }
    }
    if batch.len() > 0 {
        sec_send_end.send(Some(batch)).unwrap();
    }
}

fn start_consumers(num_workers: usize,
                   message: &Arc<Vec<u8>>,
                   signature: &Arc<Vec<u8>>,
                   sec_recv_end: &Receiver<Option<Vec<Vec<u8>>>>,
                   res_send_end: &Sender<Vec<u8>>) -> Vec<JoinHandle<()>> {
    let mut workers = vec![];
    for _ in 0..num_workers {
        let message = message.clone();
        let signature = signature.clone();
        let sec_recv_end = sec_recv_end.clone();
        let res_send_end = res_send_end.clone();
        workers.push(thread::spawn(move || {
            loop {
                let batch = match sec_recv_end.recv().unwrap() {
                    Some(batch) => batch,
                    None => return
                };
                for secret in batch {
                    if is_secret_valid(&message, &signature, &secret) {
                        res_send_end.try_send(secret).unwrap();
                        return;
                    }
                }
            }
        }));
    }
    return workers;
}

fn main() {
    let args: Vec<String> = env::args().collect();
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

    // Start one worker for each virtual cpu
    let num_workers = num_cpus::get();
    // Let buffer capacity be a multiple of number of workers
    let buffer_capacity = num_workers * 4;
    // Channel for sending secrets from the main thread to workers
    let (sec_send_end, sec_recv_end) = bounded::<Option<Vec<Vec<u8>>>>(buffer_capacity);
    // Channel for a worker to signal that it has found the answer
    let (res_send_end, res_recv_end) = bounded::<Vec<u8>>(1usize);

    // Start workers
    let workers = start_consumers(num_workers, &message, &signature, &sec_recv_end, &res_send_end);
    // Generate secrets until all secrets are sent or a worker indicates it has found the answer
    generate_secrets(&alphabet, max_len as usize, &sec_send_end, &res_recv_end);

    // Either way, tell all workers to stop
    for _ in 0..num_workers {
        sec_send_end.send(None).unwrap();
    }
    // Wait for workers to finish
    for w in workers {
        w.join().unwrap();
    }
    // Check for answer
    if res_recv_end.is_empty() {
        println!("No answer found");
    } else {
        let answer = res_recv_end.recv().unwrap();
        println!("{}", std::str::from_utf8(&answer).unwrap());
    }
}
