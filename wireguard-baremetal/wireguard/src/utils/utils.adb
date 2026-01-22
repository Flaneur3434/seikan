--  Utils - Implementation
--
--  Zero-copy span operations over byte arrays.

with System.Storage_Elements;

package body Utils
  with SPARK_Mode => Off  --  Address arithmetic requires SPARK_Mode Off
is
   use System;
   use System.Storage_Elements;

   ---------------------
   --  Span Creation
   ---------------------

   function From_Array (Arr : aliased Byte_Array) return Byte_Span is
   begin
      if Arr'Length = 0 then
         return Null_Span;
      else
         return (Ptr => Arr'Address, Len => Arr'Length);
      end if;
   end From_Array;

   function From_Address
     (Addr : System.Address;
      Len  : Natural) return Byte_Span
   is
   begin
      if Len = 0 or Addr = System.Null_Address then
         return Null_Span;
      else
         return (Ptr => Addr, Len => Len);
      end if;
   end From_Address;

   ---------------------
   --  Span Properties
   ---------------------

   function Length (Span : Byte_Span) return Natural is
   begin
      return Span.Len;
   end Length;

   function Is_Empty (Span : Byte_Span) return Boolean is
   begin
      return Span.Len = 0;
   end Is_Empty;

   function Is_Null (Span : Byte_Span) return Boolean is
   begin
      return Span.Ptr = System.Null_Address;
   end Is_Null;

   function Data (Span : Byte_Span) return System.Address is
   begin
      return Span.Ptr;
   end Data;

   ---------------------
   --  Span Slicing
   ---------------------

   function Slice
     (Span   : Byte_Span;
      Offset : Natural;
      Len    : Natural) return Byte_Span
   is
   begin
      if Len = 0 then
         return Null_Span;
      else
         return
           (Ptr => Span.Ptr + Storage_Offset (Offset),
            Len => Len);
      end if;
   end Slice;

   function Slice_From
     (Span   : Byte_Span;
      Offset : Natural) return Byte_Span
   is
      Remaining : constant Natural := Span.Len - Offset;
   begin
      if Remaining = 0 then
         return Null_Span;
      else
         return
           (Ptr => Span.Ptr + Storage_Offset (Offset),
            Len => Remaining);
      end if;
   end Slice_From;

   function First_N
     (Span : Byte_Span;
      N    : Natural) return Byte_Span
   is
   begin
      if N = 0 then
         return Null_Span;
      else
         return (Ptr => Span.Ptr, Len => N);
      end if;
   end First_N;

   function Last_N
     (Span : Byte_Span;
      N    : Natural) return Byte_Span
   is
   begin
      if N = 0 then
         return Null_Span;
      else
         return
           (Ptr => Span.Ptr + Storage_Offset (Span.Len - N),
            Len => N);
      end if;
   end Last_N;

   ---------------------
   --  Element Access
   ---------------------

   function Element
     (Span  : Byte_Span;
      Index : Natural) return Unsigned_8
   is
      --  Overlay a single byte at the computed address
      Byte_At : Unsigned_8
        with Address => Span.Ptr + Storage_Offset (Index),
             Import;
   begin
      return Byte_At;
   end Element;

   ---------------------
   --  Copy Operations
   ---------------------

   procedure Copy_To
     (Span : Byte_Span;
      Dest : out Byte_Array)
   is
      --  Overlay source bytes at span address
      Source : Byte_Array (0 .. Span.Len - 1)
        with Address => Span.Ptr, Import;
   begin
      if Span.Len > 0 then
         Dest (Dest'First .. Dest'First + Span.Len - 1) := Source;
      end if;
   end Copy_To;

   procedure Copy_From
     (Span   : Byte_Span;
      Source : Byte_Array)
   is
      --  Overlay destination bytes at span address
      Dest : Byte_Array (0 .. Source'Length - 1)
        with Address => Span.Ptr, Import;
   begin
      if Source'Length > 0 then
         Dest := Source;
      end if;
   end Copy_From;

end Utils;
