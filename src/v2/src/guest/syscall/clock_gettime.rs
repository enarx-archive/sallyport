// SPDX-License-Identifier: Apache-2.0

use super::types::Argv;
use crate::guest::alloc::{Allocator, Collect, Collector, Output, Syscall};
use crate::Result;

use libc::{c_long, clockid_t, timespec};

pub struct ClockGettime<'a> {
    pub clockid: clockid_t,
    pub tp: &'a mut timespec,
}

unsafe impl<'a> Syscall<'a> for ClockGettime<'a> {
    const NUM: c_long = libc::SYS_clock_gettime;

    type Argv = Argv<2>;
    type Ret = ();

    type Staged = Output<'a, timespec, &'a mut timespec>;
    type Committed = Self::Staged;
    type Collected = Result<()>;

    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        let tp = Output::stage(alloc, self.tp)?;
        Ok((Argv([self.clockid as _, tp.offset()]), tp))
    }

    fn collect(
        tp: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected {
        if let Ok(_) = ret {
            tp.collect(col);
        };
        ret
    }
}
