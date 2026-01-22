--  Random number generation using platform crypto backend

with Crypto.Platform;
with Interfaces.C;

package body Crypto.Random
  with SPARK_Mode => Off
is
   procedure Fill_Random (Buffer : out Byte_Array) is
   begin
      Crypto.Platform.Randombytes_Buf
        (Buffer => Buffer'Address,
         Size   => Interfaces.C.size_t (Buffer'Length));
   end Fill_Random;

end Crypto.Random;
