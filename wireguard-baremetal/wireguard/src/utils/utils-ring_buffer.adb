--  Utils.Ring_Buffer - Implementation
--
--  Ghost state tracks ownership for SPARK proofs.
--  Actual buffer operations use 'Address which is not allowed in SPARK,
--  so the body is SPARK_Mode => Off while the spec contracts are verified.

with System.Storage_Elements;

package body Utils.Ring_Buffer
  with
    SPARK_Mode    => Off,
    Refined_State =>
      (Buffer_Pool_State =>
         (Buffers,
          Free_Stack,
          Free_Top,
          Rx_Queue,
          Rx_Queue_Head,
          Rx_Queue_Tail,
          Rx_Queue_Len,
          Tx_Queue,
          Tx_Queue_Head,
          Tx_Queue_Tail,
          Tx_Queue_Len),
       Ghost_Ownership   => Owners)
is
   use System;
   use System.Storage_Elements;

   ---------------------
   --  Buffer Pool Storage (16-byte aligned)
   ---------------------

   type Buffer_Pool_Array is array (Buffer_Index) of aliased Buffer_Data
     with Alignment => Buffer_Alignment;

   Buffers : Buffer_Pool_Array;

   ---------------------
   --  Ghost Ownership State (proof only - compiled away)
   ---------------------

   Owners : Ownership_Array := (others => Free)
   with Ghost;

   ---------------------
   --  Free Stack (for available buffers)
   ---------------------

   type Index_Stack is array (Buffer_Count) of Buffer_Index;

   Free_Stack : Index_Stack := (others => 0);
   Free_Top   : Buffer_Count := 0;

   ---------------------
   --  RX/TX Queues (using Buffer type internally)
   ---------------------

   type Buffer_Array is array (Buffer_Index) of Buffer;

   Rx_Queue      : Buffer_Array := (others => Null_Buffer);
   Rx_Queue_Head : Buffer_Count := 0;
   Rx_Queue_Tail : Buffer_Count := 0;
   Rx_Queue_Len  : Buffer_Count := 0;

   Tx_Queue      : Buffer_Array := (others => Null_Buffer);
   Tx_Queue_Head : Buffer_Count := 0;
   Tx_Queue_Tail : Buffer_Count := 0;
   Tx_Queue_Len  : Buffer_Count := 0;

   ---------------------
   --  Ghost Functions
   ---------------------

   function Get_Owner (Index : Buffer_Index) return Owner_State
   is (Owners (Index));

   function Count_In_State (State : Owner_State) return Buffer_Count is
      Result : Buffer_Count := 0;
   begin
      for I in Buffer_Index loop
         if Owners (I) = State then
            Result := Result + 1;
         end if;
         pragma Loop_Invariant (Result <= I + 1);
      end loop;
      return Result;
   end Count_In_State;

   function Ownership_Conserved return Boolean is
      Total : Natural := 0;
   begin
      for State in Owner_State loop
         Total := Total + Count_In_State (State);
      end loop;
      return Total = Pool_Size;
   end Ownership_Conserved;

   ---------------------
   --  Buffer_Data_Ptr Conversion
   ---------------------

   function Is_Valid_Buffer (Ptr : Buffer_Data_Ptr) return Boolean is
   begin
      if Ptr = null then
         return False;
      end if;
      --  Check if pointer points to one of our buffers
      for I in Buffer_Index loop
         if Ptr = Buffers (I)'Access then
            return True;
         end if;
      end loop;
      return False;
   end Is_Valid_Buffer;

   function Ptr_To_Index (Ptr : Buffer_Data_Ptr) return Buffer_Index is
   begin
      for I in Buffer_Index loop
         if Ptr = Buffers (I)'Access then
            return I;
         end if;
      end loop;
      --  Should never reach here if precondition is satisfied
      return 0;
   end Ptr_To_Index;

   function Index_To_Ptr (Index : Buffer_Index) return Buffer_Data_Ptr
   is (Buffers (Index)'Access);

   ---------------------
   --  Address Conversion (for C interface compatibility)
   ---------------------

   function Is_Valid_Buffer (Ptr : System.Address) return Boolean is
      Base_Addr : constant System.Address := Buffers (0)'Address;
      Offset    : Storage_Offset;
      Index_Val : Integer;
   begin
      if Ptr = Null_Address then
         return False;
      end if;

      Offset := Ptr - Base_Addr;

      if Offset < 0 or else Offset mod Buffer_Capacity /= 0 then
         return False;
      end if;

      Index_Val := Integer (Offset / Buffer_Capacity);

      return Index_Val >= 0 and then Index_Val <= Buffer_Index'Last;
   end Is_Valid_Buffer;

   function Address_To_Index (Ptr : System.Address) return Buffer_Index is
      Base_Addr : constant System.Address := Buffers (0)'Address;
      Offset    : constant Storage_Offset := Ptr - Base_Addr;
   begin
      return Buffer_Index (Offset / Buffer_Capacity);
   end Address_To_Index;

   function Index_To_Address (Index : Buffer_Index) return System.Address
   is (Buffers (Index)'Address);

   ---------------------
   --  Descriptor Conversion
   ---------------------

   function To_Descriptor (B : Buffer) return Buffer_Descriptor is
   begin
      if not Is_Valid (B) then
         return Null_Descriptor;
      end if;
      return
        (Ptr => B.Data.all'Address,
         Len => size_t (B.Len),
         Cap => size_t (Buffer_Capacity),
         Id  => size_t (B.Id));
   end To_Descriptor;

   function From_Descriptor (D : Buffer_Descriptor) return Buffer is
   begin
      if D.Ptr = Null_Address then
         return Null_Buffer;
      end if;
      return
        (Data => Index_To_Ptr (Address_To_Index (D.Ptr)),
         Len  => Natural (D.Len),
         Id   => Address_To_Index (D.Ptr));
   end From_Descriptor;

   ---------------------
   --  Initialize
   ---------------------

   procedure Initialize is
   begin
      --  Reset ghost state
      Owners := (others => Free);

      --  Initialize free stack with all buffer indices
      for I in Buffer_Index loop
         Free_Stack (I) := I;
         pragma Loop_Invariant (for all J in 0 .. I => Free_Stack (J) = J);
      end loop;
      Free_Top := Pool_Size;

      --  Initialize queues
      Rx_Queue := (others => Null_Buffer);
      Rx_Queue_Head := 0;
      Rx_Queue_Tail := 0;
      Rx_Queue_Len := 0;

      Tx_Queue := (others => Null_Buffer);
      Tx_Queue_Head := 0;
      Tx_Queue_Tail := 0;
      Tx_Queue_Len := 0;
   end Initialize;

   ---------------------
   --  RX Path Operations (Buffer-based)
   ---------------------

   procedure Rx_Alloc (Buf : out Buffer) is
      Idx : Buffer_Index;
   begin
      if Free_Top = 0 then
         Buf := Null_Buffer;
         return;
      end if;

      --  Pop from free stack
      Free_Top := Free_Top - 1;
      Idx := Free_Stack (Free_Top);

      --  Transition: Free -> C_RxFill
      pragma Assert (Owners (Idx) = Free);
      Owners (Idx) := C_RxFill;

      --  Return buffer handle
      Buf := (Data => Buffers (Idx)'Access, Len => 0, Id => Idx);
   end Rx_Alloc;

   procedure Rx_Enqueue (Buf : Buffer) is
      Idx : constant Buffer_Index := Buf.Id;
   begin
      --  Transition: C_RxFill -> RxQ
      pragma Assert (Owners (Idx) = C_RxFill);
      Owners (Idx) := RxQ;

      --  Enqueue to RX queue
      Rx_Queue (Rx_Queue_Tail) := Buf;
      Rx_Queue_Tail := (Rx_Queue_Tail + 1) mod Pool_Size;
      Rx_Queue_Len := Rx_Queue_Len + 1;
   end Rx_Enqueue;

   procedure Rx_Dequeue (Buf : out Buffer; Success : out Boolean) is
      Idx : Buffer_Index;
   begin
      if Rx_Queue_Len = 0 then
         Buf := Null_Buffer;
         Success := False;
         return;
      end if;

      --  Dequeue from RX queue
      Buf := Rx_Queue (Rx_Queue_Head);
      Rx_Queue_Head := (Rx_Queue_Head + 1) mod Pool_Size;
      Rx_Queue_Len := Rx_Queue_Len - 1;

      Idx := Buf.Id;

      --  Transition: RxQ -> Ada_RxProcess
      pragma Assert (Owners (Idx) = RxQ);
      Owners (Idx) := Ada_RxProcess;

      Success := True;
   end Rx_Dequeue;

   procedure Rx_Complete (Buf : in out Buffer) is
      Idx : constant Buffer_Index := Buf.Id;
   begin
      --  Transition: Ada_RxProcess -> Free
      pragma Assert (Owners (Idx) = Ada_RxProcess);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;

      --  Invalidate the buffer handle
      Buf := Null_Buffer;
   end Rx_Complete;

   ---------------------
   --  TX Path Operations (Buffer-based)
   ---------------------

   procedure Tx_Alloc (Buf : out Buffer) is
      Idx : Buffer_Index;
   begin
      if Free_Top = 0 then
         Buf := Null_Buffer;
         return;
      end if;

      --  Pop from free stack
      Free_Top := Free_Top - 1;
      Idx := Free_Stack (Free_Top);

      --  Transition: Free -> Ada_TxBuild
      pragma Assert (Owners (Idx) = Free);
      Owners (Idx) := Ada_TxBuild;

      --  Return buffer handle
      Buf := (Data => Buffers (Idx)'Access, Len => 0, Id => Idx);
   end Tx_Alloc;

   procedure Tx_Ready (Buf : in out Buffer; Len : Natural) is
      Idx : constant Buffer_Index := Buf.Id;
   begin
      --  Transition: Ada_TxBuild -> Ada_TxEncrypt
      pragma Assert (Owners (Idx) = Ada_TxBuild);
      Owners (Idx) := Ada_TxEncrypt;

      --  Update length
      Buf.Len := Len;
   end Tx_Ready;

   procedure Tx_Enqueue (Buf : Buffer) is
      Idx : constant Buffer_Index := Buf.Id;
   begin
      --  Transition: Ada_TxEncrypt -> TxQ
      pragma Assert (Owners (Idx) = Ada_TxEncrypt);
      Owners (Idx) := TxQ;

      --  Enqueue to TX queue
      Tx_Queue (Tx_Queue_Tail) := Buf;
      Tx_Queue_Tail := (Tx_Queue_Tail + 1) mod Pool_Size;
      Tx_Queue_Len := Tx_Queue_Len + 1;
   end Tx_Enqueue;

   procedure Tx_Dequeue (Buf : out Buffer; Success : out Boolean) is
      Idx : Buffer_Index;
   begin
      if Tx_Queue_Len = 0 then
         Buf := Null_Buffer;
         Success := False;
         return;
      end if;

      --  Dequeue from TX queue
      Buf := Tx_Queue (Tx_Queue_Head);
      Tx_Queue_Head := (Tx_Queue_Head + 1) mod Pool_Size;
      Tx_Queue_Len := Tx_Queue_Len - 1;

      Idx := Buf.Id;

      --  Transition: TxQ -> C_TxSend
      pragma Assert (Owners (Idx) = TxQ);
      Owners (Idx) := C_TxSend;

      Success := True;
   end Tx_Dequeue;

   procedure Tx_Complete (Buf : in out Buffer) is
      Idx : constant Buffer_Index := Buf.Id;
   begin
      --  Transition: C_TxSend -> Free
      pragma Assert (Owners (Idx) = C_TxSend);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;

      --  Invalidate the buffer handle
      Buf := Null_Buffer;
   end Tx_Complete;

   ---------------------
   --  Drop/Abort Operations
   ---------------------

   procedure Rx_Drop (Buf : in out Buffer) is
      Idx : Buffer_Index;
   begin
      if not Is_Valid (Buf) then
         return;
      end if;

      Idx := Buf.Id;

      --  Remove from RX queue if queued
      --  Note: For simplicity, we just mark as Free and trust the caller
      --  In a real implementation, we'd need to scan and remove from queue

      --  Transition: any RX state -> Free
      pragma Assert (Owners (Idx) in C_RxFill | RxQ | Ada_RxProcess);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;

      --  Invalidate the buffer handle
      Buf := Null_Buffer;
   end Rx_Drop;

   procedure Tx_Drop (Buf : in out Buffer) is
      Idx : Buffer_Index;
   begin
      if not Is_Valid (Buf) then
         return;
      end if;

      Idx := Buf.Id;

      --  Remove from TX queue if queued
      --  Note: For simplicity, we just mark as Free and trust the caller
      --  In a real implementation, we'd need to scan and remove from queue

      --  Transition: any TX state -> Free
      pragma
        Assert (Owners (Idx) in Ada_TxBuild | Ada_TxEncrypt | TxQ | C_TxSend);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;

      --  Invalidate the buffer handle
      Buf := Null_Buffer;
   end Tx_Drop;

   ---------------------
   --  Statistics
   ---------------------

   function Free_Count return Natural
   is (Free_Top);

   function Rx_Queue_Count return Natural
   is (Rx_Queue_Len);

   function Tx_Queue_Count return Natural
   is (Tx_Queue_Len);

   --========================================================================--
   --  C Interface (uses Buffer_Descriptor for C compatibility)
   --========================================================================--

   procedure C_Init is
   begin
      Initialize;
   end C_Init;

   --  RX: Allocate buffer for receiving (Free -> C_RxFill)
   function C_Rx_Alloc return Buffer_Descriptor is
      Buf : Buffer;
   begin
      Rx_Alloc (Buf);
      return To_Descriptor (Buf);
   end C_Rx_Alloc;

   --  RX: Enqueue filled buffer (C_RxFill -> RxQ)
   procedure C_Rx_Enqueue (Desc : Buffer_Descriptor) is
   begin
      if Desc.Ptr /= Null_Address and then Is_Valid_Buffer (Desc.Ptr) then
         Rx_Enqueue (From_Descriptor (Desc));
      end if;
   end C_Rx_Enqueue;

   --  TX: Dequeue buffer for sending (TxQ -> C_TxSend)
   function C_Tx_Dequeue (Desc : access Buffer_Descriptor) return int is
      Buf     : Buffer;
      Success : Boolean;
   begin
      Tx_Dequeue (Buf, Success);
      if Success then
         Desc.all := To_Descriptor (Buf);
         return 1;
      else
         Desc.all := Null_Descriptor;
         return 0;
      end if;
   end C_Tx_Dequeue;

   --  TX: Complete send (C_TxSend -> Free)
   procedure C_Tx_Complete (Ptr : System.Address) is
      Buf : Buffer;
   begin
      if Ptr /= Null_Address and then Is_Valid_Buffer (Ptr) then
         Buf := From_Descriptor ((Ptr => Ptr, Len => 0, Cap => 0, Id => 0));
         Tx_Complete (Buf);
      end if;
   end C_Tx_Complete;

   --  Get buffer capacity
   function C_Buffer_Capacity return size_t is
   begin
      return size_t (Buffer_Capacity);
   end C_Buffer_Capacity;

   --  Get free count
   function C_Free_Count return size_t is
   begin
      return size_t (Free_Count);
   end C_Free_Count;

   --  Get RX queue count
   function C_Rx_Queue_Count return size_t is
   begin
      return size_t (Rx_Queue_Count);
   end C_Rx_Queue_Count;

   --  Get TX queue count
   function C_Tx_Queue_Count return size_t is
   begin
      return size_t (Tx_Queue_Count);
   end C_Tx_Queue_Count;

end Utils.Ring_Buffer;
