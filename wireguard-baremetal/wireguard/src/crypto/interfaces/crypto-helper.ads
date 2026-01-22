--  Crypto.Helper - Cryptographic Helper Functions
--
--  Secure memory operations for cryptographic data.

package Crypto.Helper
  with SPARK_Mode => On
is
   --  Securely zero memory
   --  Uses constant-time implementation to avoid compiler optimization
   procedure Memzero (Buffer : in out Byte_Array)
   with Global => null;

   --  Constant-time comparison of two buffers
   --  Returns Success if equal, Error_Failed if different
   function Cmp
     (A : Byte_Array;
      B : Byte_Array) return Status
   with
     Global => null,
     Pre    => A'Length = B'Length;

end Crypto.Helper;
