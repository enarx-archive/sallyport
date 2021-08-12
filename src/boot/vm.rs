// SPDX-License-Identifier: Apache-2.0

//! Shared components for the shim and the loader
//! # Loader
//!
//! The loader writes [`BootInfo`] to address of the first [`Block`](crate::Block) address.
//!
//! The loader starts the virtual machine and jumps to the shim entry point.
//!
//!
//! # Shim
//!
//! The shim sets the unencrypted flag for the page at `SYSCALL_PHYS_ADDR` and uses that page
//! for further communication with the host via [`Block`](crate::Block).
//!
//! To proxy a syscall to the host, the shim triggers a `#VMEXIT` via I/O on the
//! [`SYSCALL_TRIGGER_PORT`].

/// I/O port used to trigger a `#VMEXIT`
pub const SYSCALL_TRIGGER_PORT: u16 = 0xFF;

use core::fmt;
use core::hint::unreachable_unchecked;
use core::mem::MaybeUninit;
use nbytes::bytes;

/// The maximum size of the injected secret for SEV keeps
#[allow(clippy::integer_arithmetic)]
pub const SEV_SECRET_MAX_SIZE: usize = bytes!(16; KiB);

/// A 16 byte aligned SevSecret with unknown content
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
pub struct SevSecret {
    /// the secret byte blob
    pub data: MaybeUninit<[u8; SEV_SECRET_MAX_SIZE]>,
}

impl Default for SevSecret {
    fn default() -> Self {
        Self {
            data: MaybeUninit::uninit(),
        }
    }
}

impl SevSecret {
    #[allow(clippy::integer_arithmetic)]
    unsafe fn cbor_len(data: *const u8) -> Option<usize> {
        let prefix = data.read();

        // only accept CBOR BYTES type
        if (prefix >> 5) != 2 {
            return None;
        }

        // mask the minor
        match prefix & 0b00011111 {
            x @ 0..=23 => Some(1 + x as usize),
            24 => Some(1 + 1 + data.add(1).read() as usize),
            25 => {
                let data = data.add(1) as *const [u8; 2];
                Some(1 + 2 + u16::from_be_bytes(data.read()) as usize)
            }
            26 => {
                let data = data.add(1) as *const [u8; 4];
                Some(1 + 4 + u32::from_be_bytes(data.read()) as usize)
            }
            27 => {
                let data = data.add(1) as *const [u8; 8];
                Some(1 + 8 + u64::from_be_bytes(data.read()) as usize)
            }
            28 => None,
            29 => None,
            30 => None,
            31 => None,
            32..=255 => unreachable_unchecked(),
        }
    }

    /// get the length of the secret
    #[allow(dead_code)]
    pub fn try_len(&self) -> Option<usize> {
        let len = unsafe { SevSecret::cbor_len(self.data.as_ptr() as _) };
        len.filter(|len| *len <= SEV_SECRET_MAX_SIZE)
    }

    /// Get a slice of the secret
    #[allow(dead_code)]
    pub fn try_as_slice(&self) -> Option<&[u8]> {
        self.try_len()
            .map(|len| &unsafe { &*self.data.as_ptr() }[..len])
    }
}

/// Basic information for the shim
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct BootInfo {
    /// The injected secret
    pub secret: SevSecret,
    /// Memory size
    pub mem_size: usize,
}

/// Basic information about the host memory
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct MemInfo {
    /// Loader virtual address of initial shim physical memory
    pub virt_start: usize,
    /// Number of memory slot available for ballooning
    pub mem_slots: usize,
}

impl fmt::Debug for MemInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("MemInfo")
            .field(
                "virt_start",
                &format_args!("{:#?}", self.virt_start as *const u8),
            )
            .field("mem_slots", &self.mem_slots)
            .finish()
    }
}
