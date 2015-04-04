{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ViewPatterns #-}
module System.Posix.MemoryManagement
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
pattern ProtNone <- ((\p -> unProtection p .&. _protNone > 0) -> True)
  where
    ProtNone = Protection _protNone

pattern ProtRead :: Protection
pattern ProtRead <- ((\p -> unProtection p .&. _protRead > 0) -> True)
  where
    ProtRead = Protection _protRead

pattern ProtWrite :: Protection
pattern ProtWrite <- ((\p -> unProtection p .&. _protWrite > 0) -> True)
  where
    ProtWrite = Protection _protWrite

pattern ProtExec :: Protection
pattern ProtExec <- ((\p -> unProtection p .&. _protExec > 0) -> True)
  where
    ProtExec = Protection _protExec

_protNone, _protRead, _protWrite, _protExec :: CInt
_protNone = {# const PROT_NONE #}
_protRead = {# const PROT_READ #}
_protWrite = {# const PROT_WRITE #}
_protExec = {# const PROT_EXEC #}

newtype Sharing = Sharing { unSharing :: CInt }

pattern MapShared = Sharing {# const MAP_SHARED #}
pattern MapPrivate = Sharing {# const MAP_PRIVATE #}

newtype Residency = Residency { unResidency :: CUChar } deriving Storable

instance Show Residency where
  show (Residency n) = show n

pattern InCore :: Residency
pattern InCore <- ((\r -> unResidency r .&. _inCore > 0) -> True)
  where
    InCore = Residency _inCore

pattern Referenced :: Residency
pattern Referenced <- ((\r -> unResidency r .&. _referenced > 0) -> True)
  where
    Referenced = Residency _referenced

pattern Modified :: Residency
pattern Modified <- ((\r -> unResidency r .&. _modified > 0) -> True)
  where
    Modified = Residency _modified

pattern ReferencedOther :: Residency
pattern ReferencedOther <-
  ((\r -> unResidency r .&. _referencedOther > 0) -> True)
  where
    ReferencedOther = Residency _referencedOther

pattern ModifiedOther :: Residency
pattern ModifiedOther <-
  ((\r -> unResidency r .&. _modifiedOther > 0) -> True)
  where
    ModifiedOther = Residency _modifiedOther

_inCore, _referenced, _modified, _referencedOther, _modifiedOther :: CUChar
_inCore = {# const MINCORE_INCORE #}
_referenced = {# const MINCORE_REFERENCED #}
_modified = {# const MINCORE_MODIFIED #}
_referencedOther = {# const MINCORE_REFERENCED_OTHER #}
_modifiedOther = {# const MINCORE_MODIFIED_OTHER #}

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
