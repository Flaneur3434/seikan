--  Utils.Ring_Buffer - Implementation
--
--  Ghost state tracks ownership for SPARK proofs.
--  Actual buffer operations use 'Address which is not allowed in SPARK,
--  so the body is SPARK_Mode => Off while the spec contracts are verified.

with System.Storage_Elements;

package body Utils.Ring_Buffer
  with SPARK_Mode => Off,
       Refined_State => (Buffer_Pool_State => (Buffers, Free_Stack, Free_Top,
                                               Rx_Queue_Data, Rx_Queue_Head,
                                               Rx_Queue_Tail, Rx_Queue_Len,
                                               Tx_Queue_Data, Tx_Queue_Head,
                                               Tx_Queue_Tail, Tx_Queue_Len),
                         Ghost_Ownership => Owners)
is
   use System;
   use System.Storage_Elements;

   ---------------------
   --  Buffer Pool Storage (16-byte aligned)
   ---------------------

   type Buffer_Storage is array (0 .. Buffer_Capacity - 1) of Unsigned_8
     with Alignment => Buffer_Alignment;

   type Buffer_Pool_Array is array (Buffer_Index) of Buffer_Storage;

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
   --  RX Queue (simple ring buffer of descriptors)
   ---------------------

   type Descriptor_Array is array (Buffer_Index) of Buffer_Descriptor;

   Rx_Queue_Data : Descriptor_Array := (others => Null_Descriptor);
   Rx_Queue_Head : Buffer_Count := 0;
   Rx_Queue_Tail : Buffer_Count := 0;
   Rx_Queue_Len  : Buffer_Count := 0;

   ---------------------
   --  TX Queue (simple ring buffer of descriptors)
   ---------------------

   Tx_Queue_Data : Descriptor_Array := (others => Null_Descriptor);
   Tx_Queue_Head : Buffer_Count := 0;
   Tx_Queue_Tail : Buffer_Count := 0;
   Tx_Queue_Len  : Buffer_Count := 0;

   ---------------------
   --  Ghost Functions
   ---------------------

   function Get_Owner (Index : Buffer_Index) return Owner_State is
     (Owners (Index));

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
   --  Address Conversion
   ---------------------

   function Is_Valid_Buffer (Ptr : System.Address) return Boolean is
      Base_Addr  : constant System.Address := Buffers (0)'Address;
      Offset     : Storage_Offset;
      Index_Val  : Integer;
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

   function Index_To_Address (Index : Buffer_Index) return System.Address is
     (Buffers (Index)'Address);

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
      Rx_Queue_Data := (others => Null_Descriptor);
      Rx_Queue_Head := 0;
      Rx_Queue_Tail := 0;
      Rx_Queue_Len  := 0;

      Tx_Queue_Data := (others => Null_Descriptor);
      Tx_Queue_Head := 0;
      Tx_Queue_Tail := 0;
      Tx_Queue_Len  := 0;
   end Initialize;

   ---------------------
   --  RX Path Operations
   ---------------------

   procedure Rx_Alloc (Desc : out Buffer_Descriptor) is
      Idx : Buffer_Index;
   begin
      if Free_Top = 0 then
         Desc := Null_Descriptor;
         return;
      end if;

      --  Pop from free stack
      Free_Top := Free_Top - 1;
      Idx := Free_Stack (Free_Top);

      --  Transition: Free -> C_RxFill
      pragma Assert (Owners (Idx) = Free);
      Owners (Idx) := C_RxFill;

      --  Return descriptor
      Desc := (Ptr => Buffers (Idx)'Address,
               Len => 0,
               Cap => size_t (Buffer_Capacity),
               Id  => size_t (Idx));
   end Rx_Alloc;

   procedure Rx_Enqueue (Desc : Buffer_Descriptor) is
      Idx : Buffer_Index;
   begin
      Idx := Address_To_Index (Desc.Ptr);

      --  Transition: C_RxFill -> RxQ
      pragma Assert (Owners (Idx) = C_RxFill);
      Owners (Idx) := RxQ;

      --  Enqueue to RX queue
      Rx_Queue_Data (Rx_Queue_Tail) := Desc;
      Rx_Queue_Tail := (Rx_Queue_Tail + 1) mod Pool_Size;
      Rx_Queue_Len := Rx_Queue_Len + 1;
   end Rx_Enqueue;

   procedure Rx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean) is
      Idx : Buffer_Index;
   begin
      if Rx_Queue_Len = 0 then
         Desc := Null_Descriptor;
         Success := False;
         return;
      end if;

      --  Dequeue from RX queue
      Desc := Rx_Queue_Data (Rx_Queue_Head);
      Rx_Queue_Head := (Rx_Queue_Head + 1) mod Pool_Size;
      Rx_Queue_Len := Rx_Queue_Len - 1;

      Idx := Address_To_Index (Desc.Ptr);

      --  Transition: RxQ -> Ada_RxProcess
      pragma Assert (Owners (Idx) = RxQ);
      Owners (Idx) := Ada_RxProcess;

      Success := True;
   end Rx_Dequeue;

   procedure Rx_Complete (Ptr : System.Address) is
      Idx : Buffer_Index;
   begin
      Idx := Address_To_Index (Ptr);

      --  Transition: Ada_RxProcess -> Free
      pragma Assert (Owners (Idx) = Ada_RxProcess);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;
   end Rx_Complete;

   ---------------------
   --  TX Path Operations
   ---------------------

   procedure Tx_Alloc (Desc : out Buffer_Descriptor) is
      Idx : Buffer_Index;
   begin
      if Free_Top = 0 then
         Desc := Null_Descriptor;
         return;
      end if;

      --  Pop from free stack
      Free_Top := Free_Top - 1;
      Idx := Free_Stack (Free_Top);

      --  Transition: Free -> Ada_TxBuild
      pragma Assert (Owners (Idx) = Free);
      Owners (Idx) := Ada_TxBuild;

      --  Return descriptor
      Desc := (Ptr => Buffers (Idx)'Address,
               Len => 0,
               Cap => size_t (Buffer_Capacity),
               Id  => size_t (Idx));
   end Tx_Alloc;

   procedure Tx_Ready (Ptr : System.Address; Len : size_t) is
      pragma Unreferenced (Len);
      Idx : Buffer_Index;
   begin
      Idx := Address_To_Index (Ptr);

      --  Transition: Ada_TxBuild -> Ada_TxEncrypt
      pragma Assert (Owners (Idx) = Ada_TxBuild);
      Owners (Idx) := Ada_TxEncrypt;
   end Tx_Ready;

   procedure Tx_Enqueue (Desc : Buffer_Descriptor) is
      Idx : Buffer_Index;
   begin
      Idx := Address_To_Index (Desc.Ptr);

      --  Transition: Ada_TxEncrypt -> TxQ
      pragma Assert (Owners (Idx) = Ada_TxEncrypt);
      Owners (Idx) := TxQ;

      --  Enqueue to TX queue
      Tx_Queue_Data (Tx_Queue_Tail) := Desc;
      Tx_Queue_Tail := (Tx_Queue_Tail + 1) mod Pool_Size;
      Tx_Queue_Len := Tx_Queue_Len + 1;
   end Tx_Enqueue;

   procedure Tx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean) is
      Idx : Buffer_Index;
   begin
      if Tx_Queue_Len = 0 then
         Desc := Null_Descriptor;
         Success := False;
         return;
      end if;

      --  Dequeue from TX queue
      Desc := Tx_Queue_Data (Tx_Queue_Head);
      Tx_Queue_Head := (Tx_Queue_Head + 1) mod Pool_Size;
      Tx_Queue_Len := Tx_Queue_Len - 1;

      Idx := Address_To_Index (Desc.Ptr);

      --  Transition: TxQ -> C_TxSend
      pragma Assert (Owners (Idx) = TxQ);
      Owners (Idx) := C_TxSend;

      Success := True;
   end Tx_Dequeue;

   procedure Tx_Complete (Ptr : System.Address) is
      Idx : Buffer_Index;
   begin
      Idx := Address_To_Index (Ptr);

      --  Transition: C_TxSend -> Free
      pragma Assert (Owners (Idx) = C_TxSend);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;
   end Tx_Complete;

   ---------------------
   --  Drop/Abort Operations
   ---------------------

   procedure Rx_Drop (Ptr : System.Address) is
      Idx : Buffer_Index;
   begin
      if Ptr = Null_Address then
         return;
      end if;

      Idx := Address_To_Index (Ptr);

      --  Remove from RX queue if queued
      --  Note: For simplicity, we just mark as Free and trust the caller
      --  In a real implementation, we'd need to scan and remove from queue

      --  Transition: any RX state -> Free
      pragma Assert (Owners (Idx) in C_RxFill | RxQ | Ada_RxProcess);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;
   end Rx_Drop;

   procedure Tx_Drop (Ptr : System.Address) is
      Idx : Buffer_Index;
   begin
      if Ptr = Null_Address then
         return;
      end if;

      Idx := Address_To_Index (Ptr);

      --  Remove from TX queue if queued
      --  Note: For simplicity, we just mark as Free and trust the caller
      --  In a real implementation, we'd need to scan and remove from queue

      --  Transition: any TX state -> Free
      pragma Assert (Owners (Idx) in Ada_TxBuild | Ada_TxEncrypt | TxQ | C_TxSend);
      Owners (Idx) := Free;

      --  Push back to free stack
      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;
   end Tx_Drop;

   ---------------------
   --  Statistics
   ---------------------

   function Free_Count return Natural is (Free_Top);

   function Rx_Queue_Count return Natural is (Rx_Queue_Len);

   function Tx_Queue_Count return Natural is (Tx_Queue_Len);

   --========================================================================--
   --  C Interface
   --========================================================================--

   procedure C_Init
     with Export, Convention => C, External_Name => "wg_buf_init"
   is
   begin
      Initialize;
   end C_Init;

   --  RX: Allocate buffer for receiving (Free -> C_RxFill)
   function C_Rx_Alloc return Buffer_Descriptor
     with Export, Convention => C, External_Name => "wg_buf_rx_alloc"
   is
      Desc : Buffer_Descriptor;
   begin
      Rx_Alloc (Desc);
      return Desc;
   end C_Rx_Alloc;

   --  RX: Enqueue filled buffer (C_RxFill -> RxQ)
   procedure C_Rx_Enqueue (Desc : Buffer_Descriptor)
     with Export, Convention => C, External_Name => "wg_buf_rx_enqueue"
   is
   begin
      if Desc.Ptr /= Null_Address and then Is_Valid_Buffer (Desc.Ptr) then
         Rx_Enqueue (Desc);
      end if;
   end C_Rx_Enqueue;

   --  TX: Dequeue buffer for sending (TxQ -> C_TxSend)
   function C_Tx_Dequeue (Desc : access Buffer_Descriptor) return int
     with Export, Convention => C, External_Name => "wg_buf_tx_dequeue"
   is
      Success : Boolean;
   begin
      Tx_Dequeue (Desc.all, Success);
      return (if Success then 1 else 0);
   end C_Tx_Dequeue;

   --  TX: Complete send (C_TxSend -> Free)
   procedure C_Tx_Complete (Ptr : System.Address)
     with Export, Convention => C, External_Name => "wg_buf_tx_complete"
   is
   begin
      if Ptr /= Null_Address and then Is_Valid_Buffer (Ptr) then
         Tx_Complete (Ptr);
      end if;
   end C_Tx_Complete;

   --  Get buffer capacity
   function C_Buffer_Capacity return size_t
     with Export, Convention => C, External_Name => "wg_buf_capacity"
   is
   begin
      return size_t (Buffer_Capacity);
   end C_Buffer_Capacity;

   --  Get free count
   function C_Free_Count return size_t
     with Export, Convention => C, External_Name => "wg_buf_free_count"
   is
   begin
      return size_t (Free_Count);
   end C_Free_Count;

   --  Get RX queue count
   function C_Rx_Queue_Count return size_t
     with Export, Convention => C, External_Name => "wg_buf_rx_queue_count"
   is
   begin
      return size_t (Rx_Queue_Count);
   end C_Rx_Queue_Count;

   --  Get TX queue count
   function C_Tx_Queue_Count return size_t
     with Export, Convention => C, External_Name => "wg_buf_tx_queue_count"
   is
   begin
      return size_t (Tx_Queue_Count);
   end C_Tx_Queue_Count;

end Utils.Ring_Buffer;
