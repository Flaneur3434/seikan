--  Crypto.Helper - Cryptographic Helper Functions
--
--  Secure memory operations for cryptographic data.

with Utils; use Utils;

package Crypto.Helper
  with SPARK_Mode => On,
       Always_Terminates
is
   --  Securely zero any object (generic, SPARK-compatible)
   --
   --  Accepts any type (arrays, records, scalars).  The body uses
   --  a constant-time wipe imported from the crypto backend so the
   --  compiler cannot optimise the zeroing away.
   --
   --  Usage:
   --    procedure Wipe_Key is new Generic_Memzero (Key_Buffer);
   --    Wipe_Key (My_Key);
   generic
      type T (<>) is private;
   procedure Generic_Memzero (Item : in out T)
   with Global => null, Depends => (Item => Item);

   --  Constant-time comparison of two buffers
   --  Returns Success if equal, Error_Failed if different
   function Cmp (A : Byte_Array; B : Byte_Array) return Status
   with
     Global  => null,
     Depends => (Cmp'Result => (A, B)),
     Pre     => A'Length = B'Length;

end Crypto.Helper;
