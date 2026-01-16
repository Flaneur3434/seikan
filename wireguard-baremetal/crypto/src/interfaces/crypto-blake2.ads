package Crypto.Blake2
  with SPARK_Mode => On
is
   procedure Blake2s
     (Buffer_Out : out Byte_Array;
      Buffer_In  : Byte_Array;
      Key_Buffer : Byte_Array;
      Result     : out Crypto.Status)
   with Global => null;

end Crypto.Blake2;
