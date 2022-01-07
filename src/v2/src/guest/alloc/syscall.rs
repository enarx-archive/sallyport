// SPDX-License-Identifier: Apache-2.0

use super::{
    Allocator, Collect, Collector, Commit, Committer, InOutRef, InRef, Input, OutRef, Stage,
};
use crate::guest::syscall;
use crate::{item, Result};

use core::alloc::Layout;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use libc::{c_long, ENOMEM};

/// Trait implemented by allocatable syscalls.
pub unsafe trait Syscall<'a> {
    /// Syscall number.
    const NUM: c_long;

    /// The syscall argument vector.
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    type Ret;

    /// Opaque [staged value](Stage::Item) value, which returns [`Self::Committed`] when committed via [`Commit::commit`].
    ///
    /// This is primarily designed to serve as a container for dynamic data allocated within [`stage`][Self::stage].
    type Staged: Commit<Item = Self::Committed>;

    /// Opaque [committed value](Commit::Item) returned by [`Commit::commit`] called upon [`Self::Staged`], which is, in turn,
    /// passed to [`Self::collect`] to yield a [`Self::Collected`].
    type Committed;

    /// Value syscall [collects](Collect::Item) as, which corresponds to its [return value](Self::Ret).
    type Collected;

    /// Allocate dynamic data, if necessary and return resulting argument vector registers
    /// and opaque [staged value](Self::Staged) on success.
    fn stage(self, alloc: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)>;

    /// Collect the return registers and [opaque committed value](Self::Committed).
    fn collect(
        committed: Self::Committed,
        ret: Result<Self::Ret>,
        col: &impl Collector,
    ) -> Self::Collected;
}

/// Staged syscall, which holds allocated reference to syscall item within the block and [opaque staged value](Syscall::Staged).
pub struct StagedSyscall<'a, T: Syscall<'a>> {
    header_ref: InRef<'a, item::Header>,
    num_ref: InRef<'a, usize>,
    argv: Input<'a, [usize; 6], [usize; 6]>,
    ret_ref: InOutRef<'a, [usize; 2]>,
    staged: T::Staged,
    staged_size: usize,

    phantom: PhantomData<T>,
}

impl<'a, T: Syscall<'a>> Stage<'a> for T {
    type Item = StagedSyscall<'a, T>;

    #[inline]
    fn stage(self, alloc: &mut impl Allocator) -> Result<Self::Item> {
        let header_ref = alloc.allocate_input()?;
        let num_ref = alloc.allocate_input()?;
        let argv_ref = alloc.allocate_input()?;
        let ret_ref = alloc.allocate_inout()?;
        let ((argv, staged), mut staged_size) = alloc.section(|alloc| self.stage(alloc))?;
        if staged_size > 0 {
            let reminder = staged_size % align_of::<usize>();
            if reminder > 0 {
                let pad_size = align_of::<usize>() - reminder;
                staged_size += pad_size;

                let pad_layout = Layout::from_size_align(pad_size, 1).map_err(|_| ENOMEM)?;
                alloc.allocate_input_layout(pad_layout)?;
            }
        };
        Ok(Self::Item {
            header_ref,
            num_ref,
            argv: argv_ref.stage(argv.into()),
            ret_ref,
            staged,
            staged_size,

            phantom: PhantomData,
        })
    }
}

/// Committed syscall, which holds allocated reference to syscall return values within the block and [opaque committed value](Syscall::Committed).
pub struct CommittedSyscall<'a, T: Syscall<'a>> {
    ret_ref: OutRef<'a, [usize; 2]>,
    committed: T::Committed,

    phantom: PhantomData<T>,
}

impl<'a, T: Syscall<'a>> Commit for StagedSyscall<'a, T> {
    type Item = CommittedSyscall<'a, T>;

    #[inline]
    fn commit(mut self, com: &impl Committer) -> Self::Item {
        self.header_ref.copy_from(
            com,
            item::Header {
                size: size_of::<item::Syscall>() + self.staged_size,
                kind: item::Kind::Syscall,
            },
        );
        self.num_ref.copy_from(com, T::NUM as usize);
        self.argv.commit(com);
        self.ret_ref.copy_from(com, [-libc::ENOSYS as usize, 0]);
        Self::Item {
            ret_ref: self.ret_ref.commit(com),
            committed: self.staged.commit(com),

            phantom: self.phantom,
        }
    }
}

impl<'a, T: Syscall<'a>> Collect for CommittedSyscall<'a, T>
where
    syscall::Result<T::Ret>: Into<Result<T::Ret>>,
{
    type Item = T::Collected;

    #[inline]
    fn collect(self, col: &impl Collector) -> Self::Item {
        let mut ret = [0usize; 2];
        self.ret_ref.copy_to(col, &mut ret);
        let res: syscall::Result<T::Ret> = ret.into();
        T::collect(self.committed, res.into(), col)
    }
}

/// Trait implemented by allocatable syscalls, which are passed through directly to the host and do
/// not require custom data handling logic.
pub unsafe trait PassthroughSyscall {
    /// Syscall number.
    const NUM: c_long;

    /// The syscall argument vector.
    type Argv: Into<[usize; 6]>;

    /// Syscall return value.
    type Ret;

    /// Returns argument vector registers.
    fn stage(self) -> Self::Argv;
}

unsafe impl<'a, T: PassthroughSyscall> Syscall<'a> for T {
    const NUM: c_long = T::NUM;

    type Argv = T::Argv;
    type Ret = T::Ret;

    type Staged = ();
    type Committed = ();
    type Collected = Result<T::Ret>;

    fn stage(self, _: &mut impl Allocator) -> Result<(Self::Argv, Self::Staged)> {
        Ok((T::stage(self), ()))
    }

    fn collect(_: Self::Committed, ret: Result<Self::Ret>, _: &impl Collector) -> Self::Collected {
        ret
    }
}
