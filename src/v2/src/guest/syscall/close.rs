// SPDX-License-Identifier: Apache-2.0

use super::Argv;
use crate::guest::alloc::{Allocator, Collector, Syscall};
use crate::Result;

use libc::{c_int, c_long};

pub struct Close {
    pub fd: c_int,
}

unsafe impl<'a> Syscall<'a> for Close {
    const NUM: c_long = libc::SYS_close;
    const DEFAULT_RET: Self::Ret = unsafe { super::Result::errno_unchecked(libc::ENOSYS) };

    type Argv = Argv<1>;
    type Ret = super::Result<()>;

    type Staged = ();
    type Committed = ();
    type Collected = Result<()>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((Argv([self.fd as _]), ()))
    }

    fn collect(_: Self::Committed, ret: Self::Ret, _: &impl Collector) -> Result<()> {
        ret.into()
    }
}