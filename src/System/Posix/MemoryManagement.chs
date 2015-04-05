{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}
module System.Posix.MemoryManagement
  (
  -- * System calls
    mmap
  , munmap
  , madvise
  , posixMadvise
  , mlock
  , munlock
  , mprotect
  , msync
  , mincore

  -- * Constants and patterns
  , Protection
  , pattern PROT_NONE
  , pattern PROT_READ
  , pattern PROT_WRITE
  , pattern PROT_EXEC

  , MapFlags
  , pattern MAP_SHARED
  , pattern MAP_PRIVATE

  , Advice
  , pattern MADV_NORMAL
  , pattern MADV_SEQUENTIAL
  , pattern MADV_RANDOM
  , pattern MADV_WILLNEED
  , pattern MADV_DONTNEED
  , pattern MADV_FREE
  , pattern MADV_ZERO_WIRED_PAGES

  , PosixAdvice
  , pattern POSIX_MADV_NORMAL
  , pattern POSIX_MADV_SEQUENTIAL
  , pattern POSIX_MADV_RANDOM
  , pattern POSIX_MADV_WILLNEED
  , pattern POSIX_MADV_DONTNEED

  , Residency
  , pattern MINCORE_INCORE
  , pattern MINCORE_REFERENCED
  , pattern MINCORE_MODIFIED
  , pattern MINCORE_REFERENCED_OTHER
  , pattern MINCORE_MODIFIED_OTHER

  , SyncFlags
  , pattern MS_ASYNC
  , pattern MS_SYNC
  , pattern MS_INVALIDATE
  ) where

import Foreign
import Foreign.C

import Data.Vector.Storable (Vector)
import System.Posix.Types
import qualified Data.Vector.Storable as V

#include <sys/mman.h>
#include <unistd.h>

-- | Region accessibility.
newtype Protection = Protection CInt deriving Eq

instance Monoid Protection where
  mempty = PROT_NONE
  mappend (Protection p1) (Protection p2) = Protection (p1 .|. p2)

-- | No permissions at all.
pattern PROT_NONE :: Protection
pattern PROT_NONE <- ((\(Protection n) -> n .&. _PROT_NONE > 0) -> True)
  where
    PROT_NONE = Protection _PROT_NONE

-- | The pages can be read.
pattern PROT_READ :: Protection
pattern PROT_READ <- ((\(Protection n) -> n .&. _PROT_READ > 0) -> True)
  where
    PROT_READ = Protection _PROT_READ

-- | The pages can be written.
pattern PROT_WRITE :: Protection
pattern PROT_WRITE <- ((\(Protection n) -> n .&. _PROT_WRITE > 0) -> True)
  where
    PROT_WRITE = Protection _PROT_WRITE

-- | The pages can be executed.
pattern PROT_EXEC :: Protection
pattern PROT_EXEC <- ((\(Protection n) -> n .&. _PROT_EXEC > 0) -> True)
  where
    PROT_EXEC = Protection _PROT_EXEC

_PROT_NONE, _PROT_READ, _PROT_WRITE, _PROT_EXEC :: CInt
_PROT_NONE = {# const PROT_NONE #}
_PROT_READ = {# const PROT_READ #}
_PROT_WRITE = {# const PROT_WRITE #}
_PROT_EXEC = {# const PROT_EXEC #}

newtype MapFlags = MapFlags CInt deriving (Eq, Show)

-- POSIX.1-2001 flags

pattern MAP_SHARED :: MapFlags
pattern MAP_SHARED = MapFlags {# const MAP_SHARED #}

pattern MAP_PRIVATE :: MapFlags
pattern MAP_PRIVATE = MapFlags {# const MAP_PRIVATE #}

newtype Residency = Residency CUChar deriving Storable

instance Show Residency where
  show (Residency n) = show n

-- | Page is incore.
pattern MINCORE_INCORE :: Residency
pattern MINCORE_INCORE <-
  ((\(Residency c) -> c .&. _MINCORE_INCORE > 0) -> True)
  where
    MINCORE_INCORE = Residency _MINCORE_INCORE

-- | Page has been referenced by us.
pattern MINCORE_REFERENCED :: Residency
pattern MINCORE_REFERENCED <-
  ((\(Residency c) -> c .&. _MINCORE_REFERENCED > 0) -> True)
  where
    MINCORE_REFERENCED = Residency _MINCORE_REFERENCED

-- | Page has been modified by us.
pattern MINCORE_MODIFIED :: Residency
pattern MINCORE_MODIFIED <-
  ((\(Residency c) -> c .&. _MINCORE_MODIFIED > 0) -> True)
  where
    MINCORE_MODIFIED = Residency _MINCORE_MODIFIED

-- | Page has been referenced.
pattern MINCORE_REFERENCED_OTHER :: Residency
pattern MINCORE_REFERENCED_OTHER <-
  ((\(Residency c) -> c .&. _MINCORE_REFERENCED_OTHER > 0) -> True)
  where
    MINCORE_REFERENCED_OTHER = Residency _MINCORE_REFERENCED_OTHER

-- | Page has been modified.
pattern MINCORE_MODIFIED_OTHER :: Residency
pattern MINCORE_MODIFIED_OTHER <-
  ((\(Residency c) -> c .&. _MINCORE_MODIFIED_OTHER > 0) -> True)
  where
    MINCORE_MODIFIED_OTHER = Residency _MINCORE_MODIFIED_OTHER

_MINCORE_INCORE :: CUChar
_MINCORE_INCORE = {# const MINCORE_INCORE #}
_MINCORE_REFERENCED, _MINCORE_MODIFIED :: CUChar
_MINCORE_REFERENCED = {# const MINCORE_REFERENCED #}
_MINCORE_MODIFIED = {# const MINCORE_MODIFIED #}
_MINCORE_REFERENCED_OTHER, _MINCORE_MODIFIED_OTHER :: CUChar
_MINCORE_REFERENCED_OTHER = {# const MINCORE_REFERENCED_OTHER #}
_MINCORE_MODIFIED_OTHER = {# const MINCORE_MODIFIED_OTHER #}

newtype Advice = Advice CInt deriving (Eq, Show)

pattern MADV_NORMAL :: Advice
pattern MADV_NORMAL = Advice {# const MADV_NORMAL #}

pattern MADV_SEQUENTIAL :: Advice
pattern MADV_SEQUENTIAL = Advice {# const MADV_SEQUENTIAL #}

pattern MADV_RANDOM :: Advice
pattern MADV_RANDOM = Advice {# const MADV_RANDOM #}

pattern MADV_WILLNEED :: Advice
pattern MADV_WILLNEED = Advice {# const MADV_WILLNEED #}

pattern MADV_DONTNEED :: Advice
pattern MADV_DONTNEED = Advice {# const MADV_DONTNEED #}

pattern MADV_FREE :: Advice
pattern MADV_FREE = Advice {# const MADV_FREE #}

pattern MADV_ZERO_WIRED_PAGES :: Advice
pattern MADV_ZERO_WIRED_PAGES = Advice {# const MADV_ZERO_WIRED_PAGES #}

newtype PosixAdvice = PosixAdvice CInt deriving (Eq, Show)

pattern POSIX_MADV_NORMAL :: PosixAdvice
pattern POSIX_MADV_NORMAL = PosixAdvice {# const POSIX_MADV_NORMAL #}

pattern POSIX_MADV_SEQUENTIAL :: PosixAdvice
pattern POSIX_MADV_SEQUENTIAL = PosixAdvice {# const POSIX_MADV_SEQUENTIAL #}

pattern POSIX_MADV_RANDOM :: PosixAdvice
pattern POSIX_MADV_RANDOM = PosixAdvice {# const POSIX_MADV_RANDOM #}

pattern POSIX_MADV_WILLNEED :: PosixAdvice
pattern POSIX_MADV_WILLNEED = PosixAdvice {# const POSIX_MADV_WILLNEED #}

pattern POSIX_MADV_DONTNEED :: PosixAdvice
pattern POSIX_MADV_DONTNEED = PosixAdvice {# const POSIX_MADV_DONTNEED #}

newtype SyncFlags = SyncFlags CInt

-- | Return immediately. This flag is not permitted to be combined with other
-- flags.
pattern MS_ASYNC :: SyncFlags
pattern MS_ASYNC <- ((\(SyncFlags n) -> n .&. _MS_ASYNC > 0) -> True)
  where
    MS_ASYNC = SyncFlags _MS_ASYNC

-- | Perform synchronous writes.
pattern MS_SYNC :: SyncFlags
pattern MS_SYNC <- ((\(SyncFlags n) -> n .&. _MS_SYNC > 0) -> True)
  where
    MS_SYNC = SyncFlags _MS_SYNC

-- | Invalidate all cached data.
pattern MS_INVALIDATE :: SyncFlags
pattern MS_INVALIDATE <- ((\(SyncFlags n) -> n .&. _MS_INVALIDATE > 0) -> True)
  where
    MS_INVALIDATE = SyncFlags _MS_INVALIDATE

_MS_ASYNC, _MS_SYNC, _MS_INVALIDATE :: CInt
_MS_ASYNC = {# const MS_ASYNC #}
_MS_SYNC = {# const MS_SYNC #}
_MS_INVALIDATE = {# const MS_INVALIDATE #}

-- | @mmap(2)@. Allocate memory, or map files or devices into memory.
mmap
  :: Ptr a
  -> CSize
  -> Protection
  -> MapFlags
  -> Fd
  -> COff
  -> IO (Ptr a)
mmap ptr size (Protection prot) (MapFlags flags) fd offset = do
  p <- throwErrnoIf (== _MAP_FAILED) "mmap" $
    {# call mmap as _mmap #}
      (castPtr ptr)
      (fromIntegral size)
      prot
      flags
      (fromIntegral fd)
      (fromIntegral offset)
  return $! castPtr p

foreign import capi "sys/mman.h value MAP_FAILED" _MAP_FAILED :: Ptr a

-- | @munmap(2)@. Remove a mapping.
munmap
  :: Ptr a
  -> CSize
  -> IO ()
munmap ptr size = throwErrnoIfMinus1_ "munmap" $
  {# call munmap as _munmap #} (castPtr ptr) (fromIntegral size)

-- | @madvise(2)@. Give advice about use of memory.
madvise :: Ptr a -> CSize -> Advice -> IO ()
madvise ptr size (Advice advice) =
  throwErrnoIfMinus1_ "madvise" $
    {# call madvise as _madvise #} (castPtr ptr) (fromIntegral size) advice

-- | 'posixMadvise' behaves same as 'madvise' except that it uses values with
-- 'PosixAdvice' for the advice system call argument.
posixMadvise :: Ptr a -> CSize -> PosixAdvice -> IO ()
posixMadvise ptr size (PosixAdvice advice) =
  throwErrnoIfMinus1_ "posix_madvise" $
    {# call posix_madvise as _posix_madvise #}
      (castPtr ptr) (fromIntegral size) advice

-- | @mlock(2)@. Lock physical pages in memory.
mlock :: Ptr a -> CSize -> IO ()
mlock ptr size = throwErrnoIfMinus1_ "mlock" $
  {# call mlock as _mlock #} (castPtr ptr) (fromIntegral size)

-- | @munlock(2)@. Unlock physical pages in memory.
munlock :: Ptr a -> CSize -> IO ()
munlock ptr size = throwErrnoIfMinus1_ "munlock" $
  {# call munlock as _munlock #} (castPtr ptr) (fromIntegral size)

-- | @mprotect(2)@. Control the protection of pages.
mprotect :: Ptr a -> CSize -> Protection -> IO ()
mprotect ptr size (Protection prot) = throwErrnoIfMinus1_ "mprotect" $
  {# call mprotect as _mprotect #} (castPtr ptr) (fromIntegral size) prot

-- | @msync(2)@. Synchronize a mapped region.
msync :: Ptr a -> CSize -> SyncFlags -> IO ()
msync ptr size (SyncFlags flags) = throwErrnoIfMinus1_ "msync" $
  {# call msync as _msync #} (castPtr ptr) (fromIntegral size) flags

-- | @mincore(2)@. Determine residency of memory pages.
mincore :: Ptr a -> CSize -> IO (Vector Residency)
mincore ptr size = do
  pageSize <- {# call sysconf #} {# const _SC_PAGESIZE #}
  let !pages = fromIntegral $ (fromIntegral size + pageSize - 1) `div` pageSize
  fptr <- mallocForeignPtrBytes pages
  withForeignPtr fptr $ \p ->
    throwErrnoIf_ (/= 0) "mincore" $
      {# call mincore as _mincore #}
        (castPtr ptr) (fromIntegral size) (castPtr p)
  return $! V.unsafeFromForeignPtr0 fptr pages
