with Interfaces;

package Crypto
  with SPARK_Mode => On
is
   ---------------------
   --  Common Types
   ---------------------

   subtype Unsigned_8 is Interfaces.Unsigned_8;
   type Byte_Array is array (Natural range <>) of Unsigned_8;

   type Status is (Success, Error_Failed, Error_Invalid_Argument);
   function Is_Success (S : Status) return Boolean
   is (S = Success);

end Crypto;
