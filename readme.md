## Bitcoind Rust Client

This project is an attempt to port the Bitcoin core daemon (bitcoind) from C++ to the Rust programming language.  As a first step, the cryptographic primitives and serialization code along with associated unit tests are being ported to Rust.  The intent of the port is to keep the Rust code as close as possible in style, naming, organization, and structure to the C++ code to ease code review and port of future changes.  The goal of the project is to have a Rust based client fully sychronize with the Bitcoin blockchain and mine blocks.

## Why?

This is a personal project to improve my understanding of Rust and the Bitcoin core client.  Rust is a popular new language, displacing C++ in many places. Hopefully having a Rust based Bitcoin client that can be easily compared to the C++ client will bring new developers to the Bitcoin space.
