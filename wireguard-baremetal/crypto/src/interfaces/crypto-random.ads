package Crypto.Random
  with SPARK_Mode => On
is
   procedure Fill_Random (Buffer : out Byte_Array)
   with Global => null,
        Post => Buffer'Length = Buffer'Length;

end Crypto.Random;
