with Interfaces;

package Crypto.Random
  with SPARK_Mode => On
is
   subtype Unsigned_8 is Interfaces.Unsigned_8;

   type Byte_Array is array (Natural range <>) of Unsigned_8;

   procedure Fill_Random (Buffer : out Byte_Array)
   with Global => null,
        Post => Buffer'Length = Buffer'Length;

end Crypto.Random;         
