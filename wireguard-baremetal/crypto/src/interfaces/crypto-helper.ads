package Crypto.Helper
  with SPARK_Mode => On
is
   procedure Memzero (Buffer_In : out Byte_Array)
   with Global => null;

   procedure Cmp (A : Byte_Array; B : Byte_Array; Result : out Crypto.Status)
   with Pre => (A'Length = B'Length), Global => null;

end Crypto.Helper;
