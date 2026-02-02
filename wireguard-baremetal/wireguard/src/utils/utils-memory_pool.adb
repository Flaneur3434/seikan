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
   ---------------------------------------------------------------------------

   Buffers    : array (Pool_Index) of aliased Buffer;
   Free_Stack : array (Pool_Index) of Pool_Index;
   Free_Top   : Integer := -1;  --  -1 means empty

   ---------------------------------------------------------------------------
   --  Ghost Function Bodies
   ---------------------------------------------------------------------------

   function Free_Count return Valid_Count is (Free_Top + 1);

   ---------------------------------------------------------------------------
   --  Pool Operations
   ---------------------------------------------------------------------------

   procedure Initialize is
   begin
      for I in Pool_Index loop
         Buffers (I).Index := Null_Index;  --  Mark as not allocated
         Buffers (I).Data := (others => 0);
         Free_Stack (I) := I;
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
      Handle.Ptr := Buffers (Idx)'Access;
   end Allocate;

   procedure Free (Handle : in out Buffer_Handle) is
      Idx : Pool_Index;
   begin
      --  O(1) lookup via stored index
      Idx := Pool_Index (Handle.Ptr.Index);

      --  Clear sensitive data
      Handle.Ptr.Data := (others => 0);
      Handle.Ptr.Index := Null_Index;  --  Mark as not allocated
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

   ---------------------------------------------------------------------------
   --  Borrowing Operations
   ---------------------------------------------------------------------------

   function Borrow (Handle : Buffer_Handle) return Buffer_View is
   begin
      return (Data_Ptr => Handle.Ptr.Data'Access);
   end Borrow;

   procedure Borrow_Mut
     (Handle : in out Buffer_Handle;
      Ref    : out Buffer_Ref)
   is
   begin
      Ref := (Data_Ptr => Handle.Ptr.Data'Access);
   end Borrow_Mut;

   ---------------------------------------------------------------------------
   --  Borrow Accessors
   ---------------------------------------------------------------------------

   function View_Data (V : Buffer_View) return System.Address is
   begin
      return V.Data_Ptr.all'Address;
   end View_Data;

   function Ref_Data (R : Buffer_Ref) return System.Address is
   begin
      return R.Data_Ptr.all'Address;
   end Ref_Data;

   ---------------------------------------------------------------------------
   --  Buffer Access (Legacy)
   ---------------------------------------------------------------------------

   function Data (Handle : Buffer_Handle) return System.Address is
   begin
      return Handle.Ptr.Data'Address;
   end Data;

   ---------------------------------------------------------------------------
   --  C FFI Operations
   --
   --  C code receives pointer to Buffer record, enabling O(1) free.
   --  C struct layout: { int32_t index; uint8_t data[Packet_Size]; }
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
      Buf.Data := (others => 0);
      Buf.Index := Null_Index;

      Free_Top := Free_Top + 1;
      Free_Stack (Free_Top) := Idx;
   end C_Free;

end Utils.Memory_Pool;
