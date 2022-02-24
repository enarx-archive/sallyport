// SPDX-License-Identifier: Apache-2.0

#[macro_use]
pub mod testaso;

pub mod sev;
pub mod sgx;

use core::mem::size_of;

/// `get_attestation` syscall number used by the shim.
///
/// See <https://github.com/enarx/enarx-keepldr/issues/31>
#[allow(dead_code)]
pub const SYS_GETATT: i64 = 0xEA01;

/// Payload of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C, align(8))]
pub struct Payload {
    pub num: Number,
    pub argv: [usize; 4],
    pub ret: usize,
}

pub(crate) const USIZE_COUNT: usize = size_of::<Payload>() / size_of::<usize>();

impl From<&mut [usize; USIZE_COUNT]> for &mut Payload {
    #[inline]
    fn from(buf: &mut [usize; USIZE_COUNT]) -> Self {
        debug_assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>());
        unsafe { &mut *(buf as *mut _ as *mut _) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
/// Number of an [`Item`](super::Item) of [`Kind::Enarxcall`](super::Kind::Enarxcall).
pub enum Number {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_size() {
        assert_eq!(size_of::<Payload>(), USIZE_COUNT * size_of::<usize>())
    }

    #[test]
    fn tech_assignments() {
        assert_ne!(sev::TECH, sgx::TECH);
    }
}