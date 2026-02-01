--  Platform-specific bindings: Host (Linux/macOS/Windows)
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides OS-level services like random number generation.
--
--  For host builds on Linux, we use getrandom() syscall which provides
--  cryptographically secure random bytes from the kernel.

with System;
with Interfaces.C;

private package Crypto.Platform
  with SPARK_Mode => Off
is
   use Interfaces.C;

   ---------------------
   --  Random Number Generation
   ---------------------

   --  Fills buffer with cryptographically secure random bytes.
   --  Uses Linux getrandom() syscall (blocking until entropy available).
   --  Returns number of bytes written, or -1 on error.
   function Getrandom
     (Buffer : System.Address;
      Size   : size_t;
      Flags  : unsigned := 0) return long
   with Import, Convention => C, External_Name => "getrandom";

   --  Wrapper that fills entire buffer (handles partial reads)
   procedure Random_Bytes (Buffer : System.Address; Size : size_t);

end Crypto.Platform;
