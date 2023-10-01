# Marshrutka C2

![Rust workflow](https://github.com/nmalcolm/marshrutka/actions/workflows/rust.yml/badge.svg) ![License](https://img.shields.io/github/license/nmalcolm/marshrutka)

Marshrutka is a example command and control server, agent, and client written in Rust. It use authenticated secret-key encryption with XChaCha20Poly1305 over TCP for network communcation. 

Marshrutka's development began on the 19th of September 2023 and concluded on the 26th of September 2023. It's intentionally left unfinished and feature incomplete, but stable enough to run.

Each component is cross compatible with Windows, Linux, and macOS.

## Agent

The `agent` is the implant to be executed on the target machine. It has a modular command structure allowing you to easily extend it with additional modules.

Built-in Modules:

- Download: Download and execute a file from the Internet.
- Installed Applications: Fetch the applications installed on the machine.
- Process List: Fetch a list of running processes.
- System Info: Fetch basic system information.
- Kill Agent: Instruct the agent to exit.

Before compiling change `HARDCODED_KEY`, `SERVER_IP`, and `SERVER_PORT`.

## Client

The `client` is the interactive CLI app for viewing and controlling agents.

Before compiling change `HARDCODED_KEY` and `HARDCODED_PASSWORD` (the admin password).

## Server

The `server` acts as a relay between the `agent`s and the `client`.

Before compiling change `HARDCODED_KEY` and `HARDCODED_PASSWORD` (the admin password).

## Building

Run `cargo build --release` and the executables will be in the `./target/release` directory.

## Limitations and areas of concern

- The network message buffer has a fixed length of 500,000 bytes. If the buffer exceeds this an `UnknownCryptoError` will occur. This may happen for example when the command output is exceptionally large.
- Marshrutka uses a hardcoded, static symmetric key, and all `agent`s share this key. This makes it possible for a malicious actor to impersonate an `agent` and send spoofed command output.
- The `server` doesn't attach commands to command output. A malicious actor can flood the `server` and `client` with command output even before any command has been issued.
- The interactive prompt runs in one thread and the command results fetching happens in another thread. The command results printed to `stdout` can interfere with the prompt.
- Marshrutka is only designed for one operator. Command outputs are deleted from the `server` memory after being fetched by a `client`.
- The `client` does not automatically refresh the `agent`s list when a new `agent` connects to the `server`.
- The `agent` needs to be manually compiled, unlike in many other C2 frameworks.
- The `client` and `server` have a rudimentary password-based authentication system using a hardcoded password and the admin commands are encrypted using the same key.
- The `client` doesn't automatically re-render the prompt after receiving command output.
- The server doesn't implement any rate limiting.
- The use of `unwrap()` may cause panics.
- There's a lack of URL validation on the `download` module.
- There isn't any TCP connection reuse, `connect_to_server()` is called multiple times