// Starter code for ECE 459 Lab 2, Winter 2021

// YOU SHOULD MODIFY THIS FILE TO USE THREADING AND SHARED MEMORY

#![warn(clippy::all)]
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::env;

const DEFAULT_ALPHABETS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

type HmacSha256 = Hmac<Sha256>;

// Check if a JWT secret is correct
fn is_secret_valid(msg: &[u8], sig: &[u8], secret: &[u8]) -> bool {
    let mut mac = HmacSha256::new_varkey(secret).unwrap();
    mac.update(msg);
    mac.verify(sig).is_ok()
}

// Contextual info for solving a JWT
struct JwtSolver {
    alphabet: Vec<u8>, // set of possible bytes in the secret
    max_len: usize,    // max length of the secret
    msg: Vec<u8>,      // JWT message
    sig64: Vec<u8>,    // JWT signature (base64 decoded)
}

impl JwtSolver {
    // Recursively check every possible secret string,
    // returning the correct secret if it exists
    fn check_all(&self, secret: Vec<u8>) -> Option<Vec<u8>> {
        if is_secret_valid(&self.msg, &self.sig64, &secret) {
            return Some(secret);  // found it!
        }

        if secret.len() == self.max_len {
            return None;  // no secret of length <= max_len
        }

        for &c in self.alphabet.iter() {
            // allocate space for a secret one character longer  
            let mut new_secret = Vec::with_capacity(secret.len() + 1);
            // build the new secret
            new_secret.extend(secret.iter().chain(&mut [c].iter()));
            // check this secret, and recursively check longer ones
            if let Some(ans) = self.check_all(new_secret) {
                return Some(ans);
            }
        }
        None
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

    let alphabet = args
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
    let sig64 = match base64::decode_config(sig, base64::URL_SAFE_NO_PAD) {
        Ok(sig) => sig,
        Err(_) => {
            eprintln!("Invalid signature");
            return;
        }
    };

    // build the solver and run it to get the answer
    let solver = JwtSolver {
        alphabet,
        max_len: max_len as usize,
        msg,
        sig64,
    };
    let ans = solver.check_all(b"".to_vec());

    match ans {
        Some(ans) => println!(
            "{}", std::str::from_utf8(&ans).expect("answer not a valid string")
        ),
        None => println!("No answer found"),
    };
}
