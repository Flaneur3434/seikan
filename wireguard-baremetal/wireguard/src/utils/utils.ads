--  Utils - Common Utility Types
--
--  Provides fundamental types used throughout the codebase.
--
--  DESIGN INVARIANTS (from Zero-Copy Contract):
--    - Views do not outlive the buffer they reference (C12)
--    - No implicit copying of underlying data
--    - Length checks must occur before dereferencing (D14)
--    - Spans are non-owning borrowing references
--
--  SAFETY REQUIREMENTS:
--    - The caller must ensure the underlying buffer remains valid
--      for the entire lifetime of any Byte_Span derived from it
--    - After ownership transfer of a buffer, all spans become invalid
--    - Spans should not escape the scope of the owning buffer

with System;
with Interfaces;

package Utils
  with SPARK_Mode => On
is
   use Interfaces;

   ---------------------
   --  Byte Array Type
   ---------------------

   --  Unconstrained array of bytes - the fundamental data type
   type Byte_Array is array (Natural range <>) of Unsigned_8;

   ---------------------
   --  Byte Span Type
   ---------------------

   --  A non-owning view over a contiguous region of bytes.
   --  This is the core type for zero-copy operations.
   --
   --  WARNING: The span does NOT own the memory it points to.
   --  The caller must ensure the underlying buffer outlives the span.
   type Byte_Span is private;

   --  A null/empty span constant
   Null_Span : constant Byte_Span;

   ---------------------
   --  Span Creation
   ---------------------

   --  Create a span from a Byte_Array
   --  The span borrows from the array; array must outlive the span.
   function From_Array (Arr : aliased Byte_Array) return Byte_Span
     with Post => Length (From_Array'Result) = Arr'Length;

   --  Create a span from raw address and length
   --  Use only when interfacing with C or platform APIs.
   --  The caller is responsible for ensuring validity.
   function From_Address
     (Addr : System.Address;
      Len  : Natural) return Byte_Span
     with Post => Length (From_Address'Result) = Len;

   ---------------------
   --  Span Properties
   ---------------------

   --  Returns the number of bytes in the span
   function Length (Span : Byte_Span) return Natural
     with Inline;

   --  Returns True if the span has zero length
   function Is_Empty (Span : Byte_Span) return Boolean
     with Inline,
          Post => Is_Empty'Result = (Length (Span) = 0);

   --  Returns True if the span is null (no valid address)
   function Is_Null (Span : Byte_Span) return Boolean
     with Inline;

   --  Returns the base address of the span
   --  Used for interfacing with C APIs.
   function Data (Span : Byte_Span) return System.Address
     with Inline;

   ---------------------
   --  Span Slicing
   ---------------------

   --  Create a sub-span starting at Offset with given Length
   --  Precondition ensures the slice is within bounds.
   function Slice
     (Span   : Byte_Span;
      Offset : Natural;
      Len    : Natural) return Byte_Span
     with
       Pre  => Offset + Len <= Length (Span),
       Post => Length (Slice'Result) = Len;

   --  Create a sub-span from Offset to end
   function Slice_From
     (Span   : Byte_Span;
      Offset : Natural) return Byte_Span
     with
       Pre  => Offset <= Length (Span),
       Post => Length (Slice_From'Result) = Length (Span) - Offset;

   --  Create a sub-span of the first N bytes
   function First_N
     (Span : Byte_Span;
      N    : Natural) return Byte_Span
     with
       Pre  => N <= Length (Span),
       Post => Length (First_N'Result) = N;

   --  Create a sub-span of the last N bytes
   function Last_N
     (Span : Byte_Span;
      N    : Natural) return Byte_Span
     with
       Pre  => N <= Length (Span),
       Post => Length (Last_N'Result) = N;

   ---------------------
   --  Element Access
   ---------------------

   --  Read a single byte at the given index (0-based)
   function Element
     (Span  : Byte_Span;
      Index : Natural) return Unsigned_8
     with Pre => Index < Length (Span);

   ---------------------
   --  Copy Operations
   ---------------------

   --  Copy span contents to a Byte_Array
   --  This is an explicit copy when you need owned data.
   procedure Copy_To
     (Span : Byte_Span;
      Dest : out Byte_Array)
     with Pre => Dest'Length >= Length (Span);

   --  Copy from a Byte_Array to memory referenced by span
   --  Used for writing to buffer pools.
   procedure Copy_From
     (Span   : Byte_Span;
      Source : Byte_Array)
     with Pre => Length (Span) >= Source'Length;

private
   --  Internal representation: pointer + length
   --  This matches the C ABI for easy FFI interop
   type Byte_Span is record
      Ptr : System.Address := System.Null_Address;
      Len : Natural := 0;
   end record;

   Null_Span : constant Byte_Span :=
     (Ptr => System.Null_Address, Len => 0);

end Utils;
