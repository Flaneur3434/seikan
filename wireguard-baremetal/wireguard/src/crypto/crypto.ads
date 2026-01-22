with Utils;
with System;

package Crypto
  with SPARK_Mode => On
is
   ---------------------
   --  Re-export Common Types from Utils
   ---------------------

   subtype Byte_Array is Utils.Byte_Array;
   subtype Byte_Span is Utils.Byte_Span;

   --  Re-export Byte_Span operations for convenience
   function Length (Span : Byte_Span) return Natural renames Utils.Length;
   function Data (Span : Byte_Span) return System.Address
     renames Utils.Data;
   function Is_Empty (Span : Byte_Span) return Boolean
     renames Utils.Is_Empty;
   function Is_Null (Span : Byte_Span) return Boolean
     renames Utils.Is_Null;
   function From_Array (Arr : aliased Byte_Array) return Byte_Span
     renames Utils.From_Array;
   function From_Address
     (Addr : System.Address; Len : Natural) return Byte_Span
     renames Utils.From_Address;
   function Slice
     (Span : Byte_Span; Offset : Natural; Len : Natural) return Byte_Span
     renames Utils.Slice;
   function Slice_From (Span : Byte_Span; Offset : Natural) return Byte_Span
     renames Utils.Slice_From;
   function First_N (Span : Byte_Span; N : Natural) return Byte_Span
     renames Utils.First_N;
   function Last_N (Span : Byte_Span; N : Natural) return Byte_Span
     renames Utils.Last_N;
   Null_Span : Byte_Span renames Utils.Null_Span;

   ---------------------
   --  Status Type
   ---------------------

   type Status is (Success, Error_Failed, Error_Invalid_Argument);
   function Is_Success (S : Status) return Boolean
   is (S = Success);

end Crypto;
