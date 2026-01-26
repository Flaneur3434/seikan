--  Utils - Common Utility Types
--
--  Provides fundamental types used throughout the codebase.

with Interfaces;

package Utils
  with SPARK_Mode => On
is
   use Interfaces;

   ---------------------
   --  Byte Array Type
   ---------------------

   --  Unconstrained array of bytes
   type Byte_Array is array (Natural range <>) of Unsigned_8;

   ---------------------
   --  Byte Array <-> Integer Conversion (Little Endian)
   ---------------------

   subtype Bytes_4 is Byte_Array (0 .. 3);
   subtype Bytes_8 is Byte_Array (0 .. 7);

   function To_U32 (Bytes : Bytes_4) return Unsigned_32
     with Inline;

   function From_U32 (Value : Unsigned_32) return Bytes_4
     with Inline;

   function To_U64 (Bytes : Bytes_8) return Unsigned_64
     with Inline;

   function From_U64 (Value : Unsigned_64) return Bytes_8
     with Inline;

   ---------------------
   --  Status Type
   ---------------------

   type Status is (Success, Error_Failed, Error_Invalid_Argument);
   function Is_Success (S : Status) return Boolean
   is (S = Success);

end Utils;
