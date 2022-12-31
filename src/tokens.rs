use eyre::{Result, WrapErr};
use std::fs;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::ops::Range;
use std::os::fd::AsRawFd;
use nix::fcntl;
use nix::libc;

#[must_use = "either drop the lock to release or consume it to finalize"]
pub struct LockedToken {
    /// the db file, so we can drop the lock when we're done
    file: fs::File,
    range: Range<usize>,
}
impl std::fmt::Debug for LockedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockedToken").field("range", &self.range).finish()
    }
}
impl LockedToken {
    /// consume this token, removing it from the file
    pub fn consume(mut self) -> Result<()> {
        // upgrade our lock back to write &
        // overwrite our token while we hold the partial lock
        lock(&self.file, LockRange::Part(self.range.clone()), LockOp::Write, LockWait::Wait)?;
        self.file.seek(SeekFrom::Start(self.range.start as u64))?;
        self.file.write_all(&vec![b'#'; self.range.len()])?;

        // unlock to give other instances a chance to do stuff
        unlock_full(&self.file)?;

        // relock to clean up, if we can (otherwise whoever holds the lock
        // last will do it, or some admin will)
        if lock(&self.file, LockRange::WholeFile, LockOp::Write, LockWait::Try)? {
            // start at the very beginning (a very good place to start)
            self.file.seek(SeekFrom::Start(0))?;

            // filter out all consumed lines an rewrite
            let mut src = String::new();
            self.file.read_to_string(&mut src)?;
            let src: String = src.split_inclusive('\n').filter(|line| !line.starts_with('#')).collect();
            // write from the very beginning, and truncate
            self.file.seek(SeekFrom::Start(0))?;
            self.file.set_len(0)?;
            self.file.write_all(src.as_bytes())?;
        }

        // closing the file drops the lock

        Ok(())
    }
}

/// state of a token after [`Db::check_and_reserve`]
#[must_use = "either drop the lock to release or consume it to finalize"]
pub enum TokenState {
    /// token was valid & succesfully reserved
    ValidAndReserved(LockedToken),
    /// token was reserved by another process, still in use, try again later
    AlreadyReserved(Db),
    /// token was not valid, try again with this db
    Invalid(Db),
}

/// a database file of tokens
pub struct Db {
    file: fs::File,
}
impl Db {
    /// open the token database in /etc/signup-tokens for use
    pub fn open() -> Result<Self> {
        let file = fs::File::options()
            .read(true)
            .write(true)
            .open("/etc/signup-tokens")
            .wrap_err("opening tokens db")?;

        Ok(Self { file })
    }

    // NB(directxman12): fcntl locks are rentrant for a given process,
    // so we can "upgrade" our locks if we need to

    /// check if this token is valid, and reserve it if it is,
    /// converting this into a [`LockedToken`].
    pub fn check_and_reserve(mut self, token: &str) -> Result<TokenState> {
        let Some(range) = self.read_lock_and_find(token)? else {
            return Ok(TokenState::Invalid(self))
        };

        // unlock the rest of the file, except for the line we care about
        unlock_around(&self.file, range.clone())?;

        // refine our full-file lock to a write lock on the smaller region
        // to check that we have exclusive access...
        // (theoretically, this could be a get since we immediately downgrade below,
        // but :shrug:)
        if !lock(&self.file, LockRange::Part(range.clone()), LockOp::Write, LockWait::Try)? {
            return Ok(TokenState::AlreadyReserved(self))
        }
        // ... and then downgrade that to a read lock (which is sufficient to prevent others from
        // getting the write lock above, but won't block reading the whole file)
        lock(&self.file, LockRange::Part(range.clone()), LockOp::Read, LockWait::Wait)?;

        Ok(TokenState::ValidAndReserved(LockedToken {
            file: self.file,
            range,
        }))
    }

    fn read_lock_and_find(&mut self, token: &str) -> Result<Option<Range<usize>>> {
        if token.len() == 0 {
            // safety check
            return Ok(None)
        }

        // first, read-lock the file to check
        lock(&self.file, LockRange::WholeFile, LockOp::Read, LockWait::Wait)?;

        // then search, from the beginning
        self.file.seek(SeekFrom::Start(0))?;
        // NB(directxman12): it *might* be better to read this line by line
        // if the file gets really big, but not worth the effort right now
        // (and really, I don't see it getting that big)
        let src = {
            let mut src = String::new();
            self.file.read_to_string(&mut src)?;
            src
        };

        let mut newlines = src.match_indices('\n').peekable();
        let mut start = 0;
        let mut end = None;
        while let Some((eol, _)) = newlines.next() {
            // skip used token markers
            if src.as_bytes()[start] != b'#' && &src[start..eol] == token {
                end = Some(eol);
                break;
            }
            start = eol+1;
        }
        // check the last line if it isn't terminated
        if end.is_none() && start < src.len() {
            if &src[start..] == token {
                end = Some(src.len())
            }
        }

        // if we found an end, we have a match
        Ok(end.map(|end| start..end))
    }
}

#[derive(Debug)]
enum LockRange {
    WholeFile,
    Part(Range<usize>),
}
impl LockRange {
    fn as_range(&self) -> Range<usize> {
        match self {
            LockRange::WholeFile => 0..400,
            LockRange::Part(rng) => rng.clone(),
        }
    }
}
#[derive(Debug)]
enum LockOp {
    Read = libc::F_RDLCK as isize,
    Write = libc::F_WRLCK as isize,
}

#[derive(Debug)]
enum LockWait {
    Try,
    Wait
}

fn lock(file: &fs::File, range: LockRange, op: LockOp, wait: LockWait) -> Result<bool> {
    let range = range.as_range();
    // STLKW --> acquire a lock, wait if conflicting lock is held
    let info = &libc::flock {
        l_type: op as i16, // read lock
        l_whence: libc::SEEK_SET as i16, // start is relative to file start
        l_start: range.start as i64,
        l_len: range.len() as i64,
        l_pid: 0, // unused
    };
    let arg = match wait {
        LockWait::Try => fcntl::F_SETLK(info),
        LockWait::Wait => fcntl::F_SETLKW(info),
    };
    let res = match (wait, fcntl::fcntl(file.as_raw_fd(), arg)) {
        (_, Ok(_)) => Ok(true),
        // catch eacces / eagain as expected failures if this was a non-wait lock
        // standard says both are possible
        (LockWait::Try, Err(nix::errno::Errno::EACCES | nix::errno::Errno::EAGAIN)) => Ok(false),
        (_, Err(err)) => Err(err.into()),
    };
    res
}

fn unlock_full(file: &fs::File) -> Result<()> {
    // STLKW --> acquire a lock, wait if conflicting lock is held
    fcntl::fcntl(file.as_raw_fd(), fcntl::FcntlArg::F_SETLKW(&libc::flock {
        l_type: libc::F_UNLCK as i16,
        l_whence: libc::SEEK_SET as i16, // start is relative to file start
        l_start: 0,
        l_len: 0,
        l_pid: 0, // unused
    }))?;

    Ok(())
}

fn unlock_around(file: &fs::File, range: Range<usize>) -> Result<()> {
    // first, unlock up to the start of the range
    if range.start != 0 {
        fcntl::fcntl(file.as_raw_fd(), fcntl::FcntlArg::F_SETLKW(&libc::flock {
            l_type: libc::F_UNLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: range.start as i64,
            l_pid: 0,
        }))?;
    }

    // then, unlock everything after
    fcntl::fcntl(file.as_raw_fd(), fcntl::FcntlArg::F_SETLKW(&libc::flock {
        l_type: libc::F_UNLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: range.end as i64,
        l_len: 0,
        l_pid: 0,
    }))?;

    Ok(())
}
