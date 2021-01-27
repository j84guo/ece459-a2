To compile and run the program, call "cargo run --release --bin <binary-name> -- <token> <max-length> [alphabet]".

For example, "cargo run --release --bin lab2 -- eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.shNrMqeoWA3La5bOmJ9rzGtX8rh4M9fR93HVbE3JQTA 4 abcdefghijklmnopqrstuvwxyz0123456789" should return the secret string "0123".

The possible binaries (defined in Cargo.toml) are "lab2", "message-passing", and "shared-mem".

The "lab2" binary is the single-threaded JWT cracker.
The "message-passing" binary is the sample multi-threaded message passing implementation.
The "shared-mem" binary is the sample multi-threaded shared state implementation.

Note that message-passing.rs and shared-mem.rs are initially identical to main.rs, and your job
is to modify them to use threads and either message passing or shared memory for communication.

A message passing solution should rely only on channels and have no direct use of mutexes, atomics,
or other shared state primitives.

A shared state solution should have no channels. This rule applies to code from outside the standard library as well.
