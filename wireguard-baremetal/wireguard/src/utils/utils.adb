package body Utils
  with SPARK_Mode => Off
is

   ---------------------
   --  Byte Array <-> Integer Conversion (Little Endian)
   ---------------------

   function To_U32 (Bytes : Bytes_4) return Unsigned_32 is
   begin
      return Unsigned_32 (Bytes (0))
           or Shift_Left (Unsigned_32 (Bytes (1)), 8)
           or Shift_Left (Unsigned_32 (Bytes (2)), 16)
           or Shift_Left (Unsigned_32 (Bytes (3)), 24);
   end To_U32;

   function From_U32 (Value : Unsigned_32) return Bytes_4 is
   begin
      return
        (0 => Unsigned_8 (Value and 16#FF#),
         1 => Unsigned_8 (Shift_Right (Value, 8) and 16#FF#),
         2 => Unsigned_8 (Shift_Right (Value, 16) and 16#FF#),
         3 => Unsigned_8 (Shift_Right (Value, 24) and 16#FF#));
   end From_U32;

   function To_U64 (Bytes : Bytes_8) return Unsigned_64 is
   begin
      return Unsigned_64 (Bytes (0))
           or Shift_Left (Unsigned_64 (Bytes (1)), 8)
           or Shift_Left (Unsigned_64 (Bytes (2)), 16)
           or Shift_Left (Unsigned_64 (Bytes (3)), 24)
           or Shift_Left (Unsigned_64 (Bytes (4)), 32)
           or Shift_Left (Unsigned_64 (Bytes (5)), 40)
           or Shift_Left (Unsigned_64 (Bytes (6)), 48)
           or Shift_Left (Unsigned_64 (Bytes (7)), 56);
   end To_U64;

   function From_U64 (Value : Unsigned_64) return Bytes_8 is
   begin
      return
        (0 => Unsigned_8 (Value and 16#FF#),
         1 => Unsigned_8 (Shift_Right (Value, 8) and 16#FF#),
         2 => Unsigned_8 (Shift_Right (Value, 16) and 16#FF#),
         3 => Unsigned_8 (Shift_Right (Value, 24) and 16#FF#),
         4 => Unsigned_8 (Shift_Right (Value, 32) and 16#FF#),
         5 => Unsigned_8 (Shift_Right (Value, 40) and 16#FF#),
         6 => Unsigned_8 (Shift_Right (Value, 48) and 16#FF#),
         7 => Unsigned_8 (Shift_Right (Value, 56) and 16#FF#));
   end From_U64;

end Utils;
