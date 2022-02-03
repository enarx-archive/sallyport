// SPDX-License-Identifier: Apache-2.0

use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(usize)]
/// Number of an [`Item`](super::Item) of [`Kind::Gdbcall`](super::Kind::Gdbcall).
pub enum Number {
    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::Connection::write]"
    )]
    Write = 0x00,
    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::Connection::write_all]"
    )]
    WriteAll = 0x02,
    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::Connection::flush]"
    )]
    Flush = 0x03,
    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::Connection::on_session_start]"
    )]
    OnSessionStart = 0x04,

    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::ConnectionExt::read]"
    )]
    Read = 0x05,
    #[cfg_attr(
        feature = "doc",
        doc = "Call number coresponding to [gdbstub::conn::ConnectionExt::peek]"
    )]
    Peek = 0x06,
}

/// Payload of an [`Item`](super::Item) of [`Kind::Gdbcall`](super::Kind::Gdbcall).
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
