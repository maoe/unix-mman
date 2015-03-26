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
  , pattern ProtNone
  , pattern ProtRead
  , pattern ProtWrite
  , pattern ProtExec

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

newtype Protection = Protection CInt
  deriving (Eq, Num, Enum, Ord, Real, Integral)

instance Monoid Protection where
  mempty = ProtNone
  mappend (Protection p1) (Protection p2) = Protection (p1 .|. p2)

pattern ProtNone = Protection {# const PROT_NONE #}
pattern ProtRead = Protection {# const PROT_READ #}
pattern ProtWrite = Protection {# const PROT_WRITE #}
pattern ProtExec = Protection {# const PROT_EXEC #}

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
      (fromIntegral protection)
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
