--  Utils - Common Utility Types
--
--  Provides fundamental types used throughout the codebase.

with System;
with Interfaces;

package Utils
  with SPARK_Mode => On
is
   use Interfaces;
   use type System.Address;

   ---------------------
   --  Constants
   ---------------------

   --  Maximum packet size (MTU + headers + tag + alignment)
   --  Used for buffer sizing and proof bounds
   Max_Packet_Size : constant := 1560;

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

   ---------------------
   --  C Buffer Pointer
   --
   --  Opaque wrapper around System.Address for SPARK-safe C interop.
   --  Non-nullable: callers must validate before constructing.
   --  The raw address is hidden in the private part (SPARK_Mode => Off).
   ---------------------

   type C_Buffer_Ptr is private;

   function Is_Null (Ptr : C_Buffer_Ptr) return Boolean
   with Global => null;

   function To_Address (Ptr : C_Buffer_Ptr) return System.Address
   with Global => null;

   function From_Address (Addr : System.Address) return C_Buffer_Ptr
   with Spark_Mode => Off, Global => null;

private
   pragma SPARK_Mode (Off);

   type C_Buffer_Ptr is record
      Addr : System.Address := System.Null_Address;
   end record;

   function Is_Null (Ptr : C_Buffer_Ptr) return Boolean
   is (Ptr.Addr = System.Null_Address);

   function To_Address (Ptr : C_Buffer_Ptr) return System.Address
   is (Ptr.Addr);

   function From_Address (Addr : System.Address) return C_Buffer_Ptr
   is ((Addr => Addr));

end Utils;
