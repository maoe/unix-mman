{-# LANGUAGE ViewPatterns #-}
import Control.Exception
import Control.Monad
import Data.Foldable (for_)
import Foreign
import System.Environment

import Data.Vector.Storable (Vector)
import System.Posix.Files
import System.Posix.IO

import System.Posix.MMan

main :: IO ()
main = do
  args <- getArgs
  for_ args $ residency >=> print

residency :: FilePath -> IO (Vector Residency)
residency path = bracket open close $ \fd -> do
  (fromIntegral . fileSize -> size) <- getFdStatus fd
  bracket
    (mmap nullPtr size protNone MapShared fd 0)
    (flip munmap size)
    (flip mincore size)
  where
    open = openFd path ReadOnly Nothing defaultFileFlags
    close = closeFd
