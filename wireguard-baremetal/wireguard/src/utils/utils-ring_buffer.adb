--  Utils.Ring_Buffer - Implementation with SPARK ghost ownership tracking
--
--  Ghost state tracks ownership for SPARK proofs.
--  Actual buffer operations use 'Address which is not allowed in SPARK,
--  so the body is SPARK_Mode => Off while the spec contracts are verified.

with System.Storage_Elements;

package body Utils.Ring_Buffer
  with SPARK_Mode => Off,  --  Uses 'Address which is not allowed in SPARK
       Refined_State => (Buffer_Pool_State => (Buffers,
                                                Free_Stack,
                                                Free_Top,
                                                RX_Entries,
                                                RX_Head,
                                                RX_Tail,
                                                RX_Count,
                                                TX_Entries,
                                                TX_Head,
                                                TX_Tail,
                                                TX_Count),
                         Ghost_Ownership => Owners)
is
   use System;
   use System.Storage_Elements;

   ---------------------
   --  Buffer Pool Storage
   ---------------------

   type Buffer_Storage is array (0 .. Buffer_Capacity - 1) of Unsigned_8
     with Alignment => 8;

   type Buffer_Pool_Array is array (Buffer_Index) of Buffer_Storage;

   Buffers : Buffer_Pool_Array;

   ---------------------
   --  Ghost Ownership State (proof only - compiled away)
   ---------------------

   Owners : Ownership_Array := (others => Owner_Free_Pool)
     with Ghost;

   ---------------------
   --  Free Stack
   ---------------------

   type Index_Stack is array (Buffer_Count) of Buffer_Index;

   Free_Stack : Index_Stack := (others => 0);
   Free_Top   : Buffer_Count := 0;

   ---------------------
   --  Queue Entry
   ---------------------

   type Queue_Entry is record
      Index : Buffer_Index;
      Len   : Natural;
   end record;

   type Entry_Array is array (Buffer_Index) of Queue_Entry;

   RX_Entries : Entry_Array := (others => (Index => 0, Len => 0));
   RX_Head    : Buffer_Index := 0;
   RX_Tail    : Buffer_Index := 0;
   RX_Count   : Buffer_Count := 0;

   TX_Entries : Entry_Array := (others => (Index => 0, Len => 0));
   TX_Head    : Buffer_Index := 0;
   TX_Tail    : Buffer_Index := 0;
   TX_Count   : Buffer_Count := 0;

   ---------------------
   --  Ghost Functions (expression functions - no body needed)
   ---------------------

   function Get_Owner (Index : Buffer_Index) return Owner_Kind is
     (Owners (Index));

   function Count_With_Owner (Owner : Owner_Kind) return Buffer_Count is
      Result : Buffer_Count := 0;
   begin
      for I in Buffer_Index loop
         if Owners (I) = Owner then
            Result := Result + 1;
         end if;
         pragma Loop_Invariant (Result <= I + 1);
      end loop;
      return Result;
   end Count_With_Owner;

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
      Owners := (others => Owner_Free_Pool);

      for I in Buffer_Index loop
         Free_Stack (I) := I;
         pragma Loop_Invariant (for all J in 0 .. I => Free_Stack (J) = J);
      end loop;
      Free_Top := Pool_Size;

      RX_Entries := (others => (Index => 0, Len => 0));
      RX_Head := 0;
      RX_Tail := 0;
      RX_Count := 0;

      TX_Entries := (others => (Index => 0, Len => 0));
      TX_Head := 0;
      TX_Tail := 0;
      TX_Count := 0;
   end Initialize;

   ---------------------
   --  Allocate
   ---------------------

   procedure Allocate (Result : out System.Address) is
      Idx : Buffer_Index;
   begin
      if Free_Top = 0 then
         Result := Null_Address;
         return;
      end if;

      Free_Top := Free_Top - 1;
      Idx := Free_Stack (Free_Top);

      pragma Assert (Owners (Idx) = Owner_Free_Pool);
      Owners (Idx) := Owner_Application;

      Result := Buffers (Idx)'Address;
   end Allocate;

   ---------------------
   --  Free
   ---------------------

   procedure Free (Ptr : System.Address) is
      Idx : Buffer_Index;
   begin
      if Ptr = Null_Address then
         return;
      end if;

      Idx := Address_To_Index (Ptr);

      pragma Assert (Owners (Idx) = Owner_Application);
      Owners (Idx) := Owner_Free_Pool;

      Free_Stack (Free_Top) := Idx;
      Free_Top := Free_Top + 1;
   end Free;

   ---------------------
   --  RX Queue
   ---------------------

   procedure RX_Enqueue (Ptr : System.Address; Len : Natural) is
      Idx : constant Buffer_Index := Address_To_Index (Ptr);
   begin
      pragma Assert (Owners (Idx) = Owner_Application);
      Owners (Idx) := Owner_RX_Queue;

      RX_Entries (RX_Tail) := (Index => Idx, Len => Len);
      if RX_Tail = Buffer_Index'Last then
         RX_Tail := 0;
      else
         RX_Tail := RX_Tail + 1;
      end if;
      RX_Count := RX_Count + 1;
   end RX_Enqueue;

   procedure RX_Dequeue (Result : out Buffer_Descriptor) is
      E   : Queue_Entry;
      Idx : Buffer_Index;
   begin
      if RX_Count = 0 then
         Result := Null_Buffer;
         return;
      end if;

      E := RX_Entries (RX_Head);
      Idx := E.Index;

      RX_Entries (RX_Head) := (Index => 0, Len => 0);
      if RX_Head = Buffer_Index'Last then
         RX_Head := 0;
      else
         RX_Head := RX_Head + 1;
      end if;
      RX_Count := RX_Count - 1;

      pragma Assert (Owners (Idx) = Owner_RX_Queue);
      Owners (Idx) := Owner_Application;

      Result := (Ptr => Buffers (Idx)'Address, Len => size_t (E.Len));
   end RX_Dequeue;

   ---------------------
   --  TX Queue
   ---------------------

   procedure TX_Enqueue (Ptr : System.Address; Len : Natural) is
      Idx : constant Buffer_Index := Address_To_Index (Ptr);
   begin
      pragma Assert (Owners (Idx) = Owner_Application);
      Owners (Idx) := Owner_TX_Queue;

      TX_Entries (TX_Tail) := (Index => Idx, Len => Len);
      if TX_Tail = Buffer_Index'Last then
         TX_Tail := 0;
      else
         TX_Tail := TX_Tail + 1;
      end if;
      TX_Count := TX_Count + 1;
   end TX_Enqueue;

   procedure TX_Dequeue (Result : out Buffer_Descriptor) is
      E   : Queue_Entry;
      Idx : Buffer_Index;
   begin
      if TX_Count = 0 then
         Result := Null_Buffer;
         return;
      end if;

      E := TX_Entries (TX_Head);
      Idx := E.Index;

      TX_Entries (TX_Head) := (Index => 0, Len => 0);
      if TX_Head = Buffer_Index'Last then
         TX_Head := 0;
      else
         TX_Head := TX_Head + 1;
      end if;
      TX_Count := TX_Count - 1;

      pragma Assert (Owners (Idx) = Owner_TX_Queue);
      Owners (Idx) := Owner_Application;

      Result := (Ptr => Buffers (Idx)'Address, Len => size_t (E.Len));
   end TX_Dequeue;

   ---------------------
   --  Statistics
   ---------------------

   function Free_Count return Natural is (Free_Top);
   function RX_Pending return Natural is (RX_Count);
   function TX_Pending return Natural is (TX_Count);

   --========================================================================--
   --  C Interface
   --========================================================================--

   procedure C_Init
     with Export, Convention => C, External_Name => "wg_buf_init"
   is
   begin
      Initialize;
   end C_Init;

   function C_Alloc (Capacity : size_t) return System.Address
     with Export, Convention => C, External_Name => "wg_buf_alloc"
   is
      pragma Unreferenced (Capacity);
      Result : System.Address;
   begin
      Allocate (Result);
      return Result;
   end C_Alloc;

   procedure C_Free (Ptr : System.Address)
     with Export, Convention => C, External_Name => "wg_buf_free"
   is
   begin
      --  Trust caller to own the buffer (no runtime check)
      Free (Ptr);
   end C_Free;

   procedure C_RX_Enqueue (Ptr : System.Address; Len : size_t)
     with Export, Convention => C, External_Name => "wg_rx_enqueue"
   is
   begin
      if Ptr = Null_Address or else Len > size_t (Buffer_Capacity) then
         return;
      end if;
      if not Is_Valid_Buffer (Ptr) then
         return;
      end if;
      --  Trust caller to own the buffer
      RX_Enqueue (Ptr, Natural (Len));
   end C_RX_Enqueue;

   function C_RX_Dequeue return Buffer_Descriptor
     with Export, Convention => C, External_Name => "wg_rx_dequeue"
   is
      Result : Buffer_Descriptor;
   begin
      RX_Dequeue (Result);
      return Result;
   end C_RX_Dequeue;

   procedure C_TX_Enqueue (Ptr : System.Address; Len : size_t)
     with Export, Convention => C, External_Name => "wg_tx_enqueue"
   is
   begin
      if Ptr = Null_Address or else Len > size_t (Buffer_Capacity) then
         return;
      end if;
      if not Is_Valid_Buffer (Ptr) then
         return;
      end if;
      --  Trust caller to own the buffer
      TX_Enqueue (Ptr, Natural (Len));
   end C_TX_Enqueue;

   function C_TX_Dequeue return Buffer_Descriptor
     with Export, Convention => C, External_Name => "wg_tx_dequeue"
   is
      Result : Buffer_Descriptor;
   begin
      TX_Dequeue (Result);
      return Result;
   end C_TX_Dequeue;

   function C_Buffer_Capacity return size_t
     with Export, Convention => C, External_Name => "wg_buf_capacity"
   is
   begin
      return size_t (Buffer_Capacity);
   end C_Buffer_Capacity;

   function C_Free_Count return size_t
     with Export, Convention => C, External_Name => "wg_buf_free_count"
   is
   begin
      return size_t (Free_Count);
   end C_Free_Count;

end Utils.Ring_Buffer;
