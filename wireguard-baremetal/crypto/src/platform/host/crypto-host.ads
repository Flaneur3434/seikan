--  Host platform bindings for testing on Linux/macOS
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Contains host-specific functions (not in libsodium).

with System;
with Interfaces.C;

private package Crypto.Host
  with SPARK_Mode => Off
is
   --  ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
   --  Linux syscall for random bytes
   --  Returns number of bytes written, or -1 on error
   function Getrandom
     (Buf   : System.Address;
      Len   : Interfaces.C.size_t;
      Flags : Interfaces.C.unsigned) return Interfaces.C.long
   with Import, Convention => C, External_Name => "getrandom";

   --  Flag: Use /dev/urandom (non-blocking)
   GRND_NONBLOCK : constant Interfaces.C.unsigned := 1;

end Crypto.Host;
