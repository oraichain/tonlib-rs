extern crate core;

pub mod address;
pub mod cell;

pub mod message;

pub mod hashmap;

pub mod responses;

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

#[cfg(not(target_arch = "wasm32"))]
pub mod client;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod contract;
#[cfg(not(target_arch = "wasm32"))]
pub mod emulator;
#[cfg(not(target_arch = "wasm32"))]
pub mod meta;
#[cfg(not(target_arch = "wasm32"))]
pub mod mnemonic;
#[cfg(not(target_arch = "wasm32"))]
pub mod tl;
#[cfg(not(target_arch = "wasm32"))]
pub mod types;
#[cfg(not(target_arch = "wasm32"))]
pub mod wallet;
