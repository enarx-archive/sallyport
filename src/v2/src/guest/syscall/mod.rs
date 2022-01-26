// SPDX-License-Identifier: Apache-2.0

//! Syscall-specific functionality.

#[cfg(test)]
mod tests;

mod bind;
mod clock_gettime;
mod connect;
mod fcntl;
mod fstat;
mod passthrough;
mod read;
mod result;
mod setsockopt;
mod stub;
mod write;

pub mod types;

pub use bind::*;
pub use clock_gettime::*;
pub use connect::*;
pub use fcntl::Fcntl;
pub use fstat::*;
pub use passthrough::*;
pub use read::*;
pub use result::Result;
pub use setsockopt::*;
pub use stub::*;
pub use write::Write;
