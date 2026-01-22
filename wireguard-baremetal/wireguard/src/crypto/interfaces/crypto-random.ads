--  Crypto.Random - Cryptographic Random Number Generation
--
--  Provides cryptographically secure random bytes.

package Crypto.Random
  with SPARK_Mode => On
is
   --  Fill buffer with cryptographically secure random bytes
   procedure Fill_Random (Buffer : out Byte_Array)
   with Global => null;

end Crypto.Random;
