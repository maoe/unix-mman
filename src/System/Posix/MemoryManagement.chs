{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}
module System.Posix.MemoryManagement
  ( mmap
  , munmap
  , madvise
  , posixMadvise
  , mlock
  , munlock
  , mprotect
  , msync
  , mincore

  , Protection
  , pattern ProtNone
  , pattern ProtRead
  , pattern ProtWrite
  , pattern ProtExec

  , Sharing
  , pattern MapShared
  , pattern MapPrivate

  , Advice(..)
  , PosixAdvice(..)

  , Residency
  , pattern InCore
  , pattern Referenced
  , pattern Modified
  , pattern ReferencedOther
  , pattern ModifiedOther

  , SyncFlags
  , pattern Async
  , pattern Sync
  , pattern Invalidate
  ) where

import Foreign
import Foreign.C

import Data.Vector.Storable (Vector)
import System.Posix.Types
import qualified Data.Vector.Storable as V

#include <sys/mman.h>
#include <unistd.h>

newtype Protection = Protection { unProtection :: CInt } deriving Eq

instance Monoid Protection where
  mempty = ProtNone
  mappend (Protection p1) (Protection p2) = Protection (p1 .|. p2)

pattern ProtNone :: Protection
pattern ProtNone <- ((\p -> unProtection p .&. _PROT_NONE > 0) -> True)
  where
    ProtNone = Protection _PROT_NONE

pattern ProtRead :: Protection
pattern ProtRead <- ((\p -> unProtection p .&. _PROT_READ > 0) -> True)
  where
    ProtRead = Protection _PROT_READ

pattern ProtWrite :: Protection
pattern ProtWrite <- ((\p -> unProtection p .&. _PROT_WRITE > 0) -> True)
  where
    ProtWrite = Protection _PROT_WRITE

pattern ProtExec :: Protection
pattern ProtExec <- ((\p -> unProtection p .&. _PROT_EXEC > 0) -> True)
  where
    ProtExec = Protection _PROT_EXEC

_PROT_NONE, _PROT_READ, _PROT_WRITE, _PROT_EXEC :: CInt
_PROT_NONE = {# const PROT_NONE #}
_PROT_READ = {# const PROT_READ #}
_PROT_WRITE = {# const PROT_WRITE #}
_PROT_EXEC = {# const PROT_EXEC #}

newtype Sharing = Sharing { unSharing :: CInt }

pattern MapShared = Sharing {# const MAP_SHARED #}
pattern MapPrivate = Sharing {# const MAP_PRIVATE #}

newtype Residency = Residency { unResidency :: CUChar } deriving Storable

instance Show Residency where
  show (Residency n) = show n

pattern InCore :: Residency
pattern InCore <-
  ((\r -> unResidency r .&. _MINCORE_INCORE > 0) -> True)
  where
    InCore = Residency _MINCORE_INCORE

pattern Referenced :: Residency
pattern Referenced <-
  ((\r -> unResidency r .&. _MINCORE_REFERENCED > 0) -> True)
  where
    Referenced = Residency _MINCORE_REFERENCED

pattern Modified :: Residency
pattern Modified <-
  ((\r -> unResidency r .&. _MINCORE_MODIFIED > 0) -> True)
  where
    Modified = Residency _MINCORE_MODIFIED

pattern ReferencedOther :: Residency
pattern ReferencedOther <-
  ((\r -> unResidency r .&. _MINCORE_REFERENCED_OTHER > 0) -> True)
  where
    ReferencedOther = Residency _MINCORE_REFERENCED_OTHER

pattern ModifiedOther :: Residency
pattern ModifiedOther <-
  ((\r -> unResidency r .&. _MINCORE_MODIFIED_OTHER > 0) -> True)
  where
    ModifiedOther = Residency _MINCORE_MODIFIED_OTHER

_MINCORE_INCORE :: CUChar
_MINCORE_INCORE = {# const MINCORE_INCORE #}
_MINCORE_REFERENCED = {# const MINCORE_REFERENCED #}
_MINCORE_MODIFIED = {# const MINCORE_MODIFIED #}
_MINCORE_REFERENCED_OTHER = {# const MINCORE_REFERENCED_OTHER #}
_MINCORE_MODIFIED_OTHER = {# const MINCORE_MODIFIED_OTHER #}

mmap
  :: Ptr a
  -> CSize
  -> Protection
  -> Sharing
  -> Fd
  -> COff
  -> IO (Ptr a)
mmap ptr size protection sharing fd offset = do
  p <- throwErrnoIf (== _MAP_FAILED) "mmap" $
    {# call mmap as _mmap #}
      (castPtr ptr)
      (fromIntegral size)
      (unProtection protection)
      (unSharing sharing)
      (fromIntegral fd)
      (fromIntegral offset)
  return $! castPtr p

foreign import capi "sys/mman.h value MAP_FAILED" _MAP_FAILED :: Ptr a

munmap
  :: Ptr a
  -> CSize
  -> IO ()
munmap ptr size = throwErrnoIfMinus1_ "munmap" $
  {# call munmap as _munmap #} (castPtr ptr) (fromIntegral size)

{# enum define Advice
  { MADV_NORMAL as MADV_NORMAL
  , MADV_SEQUENTIAL as MADV_SEQUENTIAL
  , MADV_RANDOM as MADV_RANDOM
  , MADV_WILLNEED as MADV_WILLNEED
  , MADV_DONTNEED as MADV_DONTNEED
  , MADV_FREE as MADV_FREE
  , MADV_ZERO_WIRED_PAGES as MADV_ZERO_WIRED_PAGES
  } deriving (Eq, Show)
  #}

{# enum define PosixAdvice
  { POSIX_MADV_NORMAL as POSIX_MADV_NORMAL
  , POSIX_MADV_SEQUENTIAL as POSIX_MADV_SEQUENTIAL
  , POSIX_MADV_RANDOM as POSIX_MADV_RANDOM
  , POSIX_MADV_WILLNEED as POSIX_MADV_WILLNEED
  , POSIX_MADV_DONTNEED as POSIX_MADV_DONTNEED
  } deriving (Eq, Show)
  #}

madvise :: Ptr a -> CSize -> Advice -> IO ()
madvise ptr size advice =
  throwErrnoIfMinus1_ "madvise" $
    {# call madvise as _madvise #}
      (castPtr ptr) (fromIntegral size) (fromIntegral (fromEnum advice))

posixMadvise :: Ptr a -> CSize -> PosixAdvice -> IO ()
posixMadvise ptr size advice =
  throwErrnoIfMinus1_ "posix_madvise" $
    {# call posix_madvise as _posix_madvise #}
      (castPtr ptr) (fromIntegral size) (fromIntegral (fromEnum advice))

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

mlock :: Ptr a -> CSize -> IO ()
mlock ptr size = throwErrnoIfMinus1_ "mlock" $
  {# call mlock as _mlock #} (castPtr ptr) (fromIntegral size)

munlock :: Ptr a -> CSize -> IO ()
munlock ptr size = throwErrnoIfMinus1_ "munlock" $
  {# call munlock as _munlock #} (castPtr ptr) (fromIntegral size)

mprotect :: Ptr a -> CSize -> Protection -> IO ()
mprotect ptr size protection = throwErrnoIfMinus1_ "mprotect" $
  {# call mprotect as _mprotect #}
    (castPtr ptr) (fromIntegral size) (unProtection protection)

newtype SyncFlags = SyncFlags { unSyncFlags :: CInt }

pattern Async :: SyncFlags
pattern Async <- ((\flags -> unSyncFlags flags .&. _MS_ASYNC > 0) -> True)
  where
    Async = SyncFlags _MS_ASYNC

pattern Sync :: SyncFlags
pattern Sync <- ((\flags -> unSyncFlags flags .&. _MS_SYNC > 0) -> True)
  where
    Sync = SyncFlags _MS_SYNC

pattern Invalidate :: SyncFlags
pattern Invalidate <-
  ((\flags -> unSyncFlags flags .&. _MS_INVALIDATE > 0) -> True)
  where
    Invalidate = SyncFlags _MS_INVALIDATE

_MS_ASYNC, _MS_SYNC, _MS_INVALIDATE :: CInt
_MS_ASYNC = {# const MS_ASYNC #}
_MS_SYNC = {# const MS_SYNC #}
_MS_INVALIDATE = {# const MS_INVALIDATE #}

msync :: Ptr a -> CSize -> SyncFlags -> IO ()
msync ptr size flags = throwErrnoIfMinus1_ "msync" $
  {# call msync as _msync #} (castPtr ptr) (fromIntegral size) (unSyncFlags flags)
