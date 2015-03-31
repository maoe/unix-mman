{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}
module System.Posix.MMan
  ( mmap
  , munmap
  -- , madvice
  -- , mlock
  -- , munlock
  -- , mprotect
  -- , msync
  , mincore

  , Protection
  , protNone
  , protRead
  , protWrite
  , protExec
  , isProtNone
  , isProtRead
  , isProtWrite
  , isProtExec

  , Sharing
  , pattern MapShared
  , pattern MapPrivate

  , Residency
  , pattern InCore
  , pattern Referenced
  , pattern Modified
  , pattern ReferencedOther
  , pattern ModifiedOther
  ) where

import Data.Monoid
import Foreign
import Foreign.C

import Data.Vector.Storable (Vector)
import System.Posix.Types
import qualified Data.Vector.Storable as V

#include <sys/mman.h>
#include <unistd.h>

newtype Protection = Protection { unProtection :: CInt } deriving Eq

instance Monoid Protection where
  mempty = protNone
  mappend (Protection p1) (Protection p2) = Protection (p1 .|. p2)

protNone, protRead, protWrite, protExec :: Protection
protNone = Protection {# const PROT_NONE #}
protRead = Protection {# const PROT_READ #}
protWrite = Protection {# const PROT_WRITE #}
protExec = Protection {# const PROT_EXEC #}

isProtNone, isProtRead, isProtWrite, isProtExec :: Protection -> Bool
isProtNone p = p == protNone
isProtRead (Protection p) = p .&. unProtection protRead > 0
isProtWrite (Protection p) = p .&. unProtection protWrite > 0
isProtExec (Protection p) = p .&. unProtection protExec > 0

newtype Sharing = Sharing CInt
  deriving (Eq, Num, Enum, Ord, Real, Integral)

pattern MapShared = Sharing {# const MAP_SHARED #}
pattern MapPrivate = Sharing {# const MAP_PRIVATE #}

newtype Residency = Residency CChar deriving Storable

instance Show Residency where
  show (Residency n) = show n

pattern InCore = Residency {# const MINCORE_INCORE #}
pattern Referenced = Residency {# const MINCORE_REFERENCED #}
pattern Modified = Residency {# const MINCORE_MODIFIED #}
pattern ReferencedOther = Residency {# const MINCORE_REFERENCED_OTHER #}
pattern ModifiedOther = Residency {# const MINCORE_MODIFIED_OTHER #}

mmap
  :: Ptr a
  -> CSize
  -> Protection
  -> Sharing
  -> Fd
  -> COff
  -> IO (Ptr a)
mmap ptr size protection sharing fd offset = do
  p <- throwErrnoIf (== c_MAP_FAILED) "mmap" $
    {# call mmap as c_mmap #}
      (castPtr ptr)
      (fromIntegral size)
      (unProtection protection)
      (fromIntegral sharing)
      (fromIntegral fd)
      (fromIntegral offset)
  return $! castPtr p

foreign import capi "sys/mman.h value MAP_FAILED" c_MAP_FAILED :: Ptr a

munmap
  :: Ptr a
  -> CSize
  -> IO ()
munmap ptr size = throwErrnoIfMinus1_ "munmap" $
  {# call munmap as c_munmap #} (castPtr ptr) (fromIntegral size)

mincore :: Ptr a -> CSize -> IO (Vector Residency)
mincore ptr size = do
  pageSize <- {# call sysconf #} {# const _SC_PAGESIZE #}
  let !len = fromIntegral $ (fromIntegral size + pageSize - 1) `div` pageSize
  fptr <- mallocForeignPtrBytes len
  withForeignPtr fptr $ \p ->
    throwErrnoIf_ (/= 0) "mincore" $
      {# call mincore as c_mincore #}
        (castPtr ptr) (fromIntegral len) (castPtr p)
  return $! V.unsafeFromForeignPtr0 fptr len
