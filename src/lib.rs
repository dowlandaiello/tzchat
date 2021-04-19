#![feature(result_flattening)]

#[macro_use]
extern crate actix;

extern crate actix_web;

#[macro_use]
extern crate log;

pub mod http_entry;
pub mod hub;
