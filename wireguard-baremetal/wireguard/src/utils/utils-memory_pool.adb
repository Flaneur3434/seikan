with Ada.Unchecked_Conversion;

package body Utils.Memory_Pool
  with SPARK_Mode => Off  --  Body uses access types directly
is
   use System;

   ---------------------------------------------------------------------------
   --  Internal State
   --
   --  Static array of buffers. Each buffer stores its own index for O(1) free.
   --  Free_Stack tracks which indices are available (LIFO).
   --  Borrow_Flags tracks which buffers have active mutable borrows.
   ---------------------------------------------------------------------------

   Buffers      : array (Pool_Index) of aliased Buffer;
   Free_Stack   : array (Pool_Index) of Pool_Index;
   Free_Top     : Integer := -1;  --  -1 means empty
   Borrow_Flags : array (Pool_Index) of Boolean := (others => False);

   ---------------------------------------------------------------------------
   --  Ghost Function Bodies
   ---------------------------------------------------------------------------

   function Free_Count return Valid_Count is (Free_Top + 1);

   function Is_Mutably_Borrowed (H : Buffer_Handle) return Boolean is
   begin
      if H.Ptr = null or else H.Ptr.Index = Null_Index then
         return False;
      end if;
      return Borrow_Flags (Pool_Index (H.Ptr.Index));
   end Is_Mutably_Borrowed;

   ---------------------------------------------------------------------------
   --  Pool Operations
   ---------------------------------------------------------------------------

   procedure Initialize is
   begin
      for I in Pool_Index loop
         Buffers (I).Index := Null_Index;  --  Mark as not allocated
         Buffers (I).Len := 0;
         Buffers (I).Offset := 0;
         Buffers (I).Data := (others => 0);
         Free_Stack (I) := I;
         Borrow_Flags (I) := False;
      end loop;
      Free_Top := Pool_Size - 1;
   end Initialize;

   procedure Allocate (Handle : out Buffer_Handle) is
      Idx : Pool_Index;
   begin
      if Free_Top < 0 then
         Handle.Ptr := null;
         return;
      end if;

      Idx := Free_Stack (Free_Top);
      Free_Top := Free_Top - 1;
      Buffers (Idx).Index := Buffer_Index (Idx);  --  Mark as allocated
      Buffers (Idx).Len := 0;
      Buffers (Idx).Offset := 0;
      Handle.Ptr := Buffers (Idx)'Access;
   end Allocate;

   procedure Free (Handle : in out Buffer_Handle) is
      Idx : Pool_Index;
   begin
      --  O(1) lookup via stored index
      Idx := Pool_Index (Handle.Ptr.Index);

      --  Clear metadata and sensitive data
      Handle.Ptr.Index := Null_Index;  --  Mark as not allocated
      Handle.Ptr.Len := 0;
      Handle.Ptr.Offset := 0;
      Handle.Ptr.Data := (others => 0);
      Handle.Ptr := null;

      Free_Top := Free_Top + 1;
      Free_Stack (Free_Top) := Idx;
   end Free;

   ---------------------------------------------------------------------------
   --  Ownership Transfer
   ---------------------------------------------------------------------------

   procedure Move (From : in out Buffer_Handle; To : out Buffer_Handle) is
   begin
      To.Ptr := From.Ptr;
      From.Ptr := null;
   end Move;

   procedure Reset_Handle (Handle : in out Buffer_Handle) is
   begin
      Handle.Ptr := null;
   end Reset_Handle;

   ---------------------------------------------------------------------------
   --  Borrowing Operations
   ---------------------------------------------------------------------------

   function Borrow (Handle : Buffer_Handle) return Buffer_View is
   begin
      if Handle.Ptr = null then
         return (Buf_Ptr => null);
      end if;
      return (Buf_Ptr => Handle.Ptr.all'Access);
   end Borrow;

   procedure Borrow_Mut
     (Handle : in out Buffer_Handle;
      Ref    : out Buffer_Ref)
   is
   begin
      if Handle.Ptr = null then
         Ref := (Buf_Ptr => null);
         return;
      end if;
      Borrow_Flags (Pool_Index (Handle.Ptr.Index)) := True;
      Ref := (Buf_Ptr => Handle.Ptr);
   end Borrow_Mut;

   procedure Return_Ref
     (Handle : in out Buffer_Handle;
      Ref    : in out Buffer_Ref)
   is
   begin
      if Handle.Ptr /= null then
         Borrow_Flags (Pool_Index (Handle.Ptr.Index)) := False;
      end if;
      Ref := (Buf_Ptr => null);
   end Return_Ref;

   ---------------------------------------------------------------------------
   --  C FFI Operations
   --
   --  C code receives pointer to wg_packet_t (Buffer record):
   --    struct { int32_t index; uint16_t len/offset; uint8_t data[]; }
   ---------------------------------------------------------------------------

   function C_Allocate return System.Address is
      Idx : Pool_Index;
   begin
      if Free_Top < 0 then
         return Null_Address;
      end if;

      Idx := Free_Stack (Free_Top);
      Free_Top := Free_Top - 1;
      Buffers (Idx).Index := Buffer_Index (Idx);
      Buffers (Idx).Len := 0;
      Buffers (Idx).Offset := 0;
      return Buffers (Idx)'Address;  --  Return Buffer record address
   end C_Allocate;

   procedure C_Free (Buf_Addr : System.Address) is
      type Buffer_Ptr is access all Buffer;
      function To_Ptr is new Ada.Unchecked_Conversion
        (System.Address, Buffer_Ptr);
      Buf : Buffer_Ptr;
      Idx : Pool_Index;
   begin
      if Buf_Addr = Null_Address then
         return;
      end if;

      Buf := To_Ptr (Buf_Addr);

      --  Validate index is in range (defensive check)
      if Buf.Index < 0 or else Buf.Index > Pool_Index'Last then
         return;
      end if;

      --  O(1) lookup via stored index
      Idx := Pool_Index (Buf.Index);
      Buf.Index := Null_Index;
      Buf.Len := 0;
      Buf.Offset := 0;
      Buf.Data := (others => 0);

      Free_Top := Free_Top + 1;
      Free_Stack (Free_Top) := Idx;
   end C_Free;

   procedure Create_From_Address
     (Addr   : System.Address;
      Handle : out Buffer_Handle)
   is
      function To_Ptr is new Ada.Unchecked_Conversion
        (System.Address, Buffer_Ptr);
   begin
      if Addr = Null_Address then
         Handle.Ptr := null;
      else
         Handle.Ptr := To_Ptr (Addr);
      end if;
   end Create_From_Address;

end Utils.Memory_Pool;
