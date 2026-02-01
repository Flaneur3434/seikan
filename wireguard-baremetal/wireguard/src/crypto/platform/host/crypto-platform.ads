--  Platform-specific bindings: Host (Linux/macOS/Windows)
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides OS-level services like random number generation.
--
--  For host builds, we use libsodium's randombytes_buf which internally
--  uses the OS's secure random source (getrandom, /dev/urandom, etc.)

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
   --  Uses the OS's secure random source via libsodium.
   procedure Random_Bytes (Buffer : System.Address; Size : size_t)
   with Import, Convention => C, External_Name => "randombytes_buf";

end Crypto.Platform;
