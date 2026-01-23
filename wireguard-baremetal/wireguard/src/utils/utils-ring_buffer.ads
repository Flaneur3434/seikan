--  Utils.Ring_Buffer - Ring buffer with SPARK-proven ownership semantics
--
--  Provides pre-allocated buffer pools for RX/TX packet handling.
--  Uses ghost state to formally track and prove buffer ownership.
--
--  Ownership Model (formally verified in SPARK code):
--    Owner_Free_Pool  : Available for allocation
--    Owner_Application: Allocated, held by Ada/C code
--    Owner_RX_Queue   : Queued for RX processing
--    Owner_TX_Queue   : Queued for TX transmission
--
--  NOTE: Ownership is tracked via ghost state for SPARK proofs only.
--        Runtime code (SPARK_Mode => Off, C code) must be careful!
--
--  C Interface:
--    wg_buf_init()           - Initialize buffer pool
--    wg_buf_alloc(cap)       - Allocate buffer (NULL if exhausted)
--    wg_buf_free(ptr)        - Return buffer to pool
--    wg_rx_enqueue(ptr, len) - Queue received packet
--    wg_rx_dequeue()         - Get next RX packet
--    wg_tx_enqueue(ptr, len) - Queue packet for transmission
--    wg_tx_dequeue()         - Get next TX packet

pragma Unevaluated_Use_Of_Old (Allow);

with System;
with Interfaces.C; use Interfaces.C;

package Utils.Ring_Buffer
  with SPARK_Mode,
       Abstract_State => (Buffer_Pool_State, Ghost_Ownership),
       Initializes => (Buffer_Pool_State, Ghost_Ownership)
is
   use type System.Address;

   ---------------------
   --  Configuration
   ---------------------

   Buffer_Capacity : constant := 1560;  --  MTU (1500) + headers
   Pool_Size       : constant := 16;    --  Number of buffers

   subtype Buffer_Index is Natural range 0 .. Pool_Size - 1;
   subtype Buffer_Count is Natural range 0 .. Pool_Size;

   ---------------------
   --  Ownership Model (Ghost Types - proof only, no runtime cost)
   ---------------------

   type Owner_Kind is (Owner_Free_Pool,
                       Owner_Application,
                       Owner_RX_Queue,
                       Owner_TX_Queue)
     with Ghost;

   type Ownership_Array is array (Buffer_Index) of Owner_Kind
     with Ghost;

   ---------------------
   --  Ghost State Queries
   ---------------------

   function Get_Owner (Index : Buffer_Index) return Owner_Kind
     with Ghost,
          Global => (Input => Ghost_Ownership);

   function Count_With_Owner (Owner : Owner_Kind) return Buffer_Count
     with Ghost,
          Global => (Input => Ghost_Ownership);

   function Ownership_Conserved return Boolean is
     (Count_With_Owner (Owner_Free_Pool) +
      Count_With_Owner (Owner_Application) +
      Count_With_Owner (Owner_RX_Queue) +
      Count_With_Owner (Owner_TX_Queue) = Pool_Size)
     with Ghost,
          Global => (Input => Ghost_Ownership);

   ---------------------
   --  Buffer Address Operations
   ---------------------

   function Is_Valid_Buffer (Ptr : System.Address) return Boolean
     with Global => (Input => Buffer_Pool_State);

   function Address_To_Index (Ptr : System.Address) return Buffer_Index
     with Global => (Input => Buffer_Pool_State),
          Pre => Is_Valid_Buffer (Ptr);

   function Index_To_Address (Index : Buffer_Index) return System.Address
     with Global => (Input => Buffer_Pool_State),
          Post => Is_Valid_Buffer (Index_To_Address'Result);

   ---------------------
   --  Buffer Descriptor (C-compatible)
   ---------------------

   type Buffer_Descriptor is record
      Ptr : System.Address;
      Len : size_t;
   end record
     with Convention => C;

   Null_Buffer : constant Buffer_Descriptor :=
     (Ptr => System.Null_Address, Len => 0);

   ---------------------
   --  Core Operations with Ownership Contracts
   ---------------------

   procedure Initialize
     with Global => (Output => (Buffer_Pool_State, Ghost_Ownership)),
          Post => (for all I in Buffer_Index =>
                     Get_Owner (I) = Owner_Free_Pool)
                  and Count_With_Owner (Owner_Free_Pool) = Pool_Size
                  and Ownership_Conserved;

   procedure Allocate (Result : out System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if Result = System.Null_Address
                       then Count_With_Owner (Owner_Free_Pool) = 0
                       else Is_Valid_Buffer (Result)
                            and Get_Owner (Address_To_Index (Result))
                                = Owner_Application
                            and Count_With_Owner (Owner_Free_Pool) =
                                Count_With_Owner (Owner_Free_Pool)'Old - 1);

   procedure Free (Ptr : System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved
                 and (Ptr = System.Null_Address
                      or else (Is_Valid_Buffer (Ptr)
                               and then Get_Owner (Address_To_Index (Ptr))
                                        = Owner_Application)),
          Post => Ownership_Conserved
                  and (if Ptr /= System.Null_Address
                          and Is_Valid_Buffer (Ptr)
                       then Get_Owner (Address_To_Index (Ptr))
                            = Owner_Free_Pool);

   procedure RX_Enqueue (Ptr : System.Address; Len : Natural)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved
                 and then Is_Valid_Buffer (Ptr)
                 and then Get_Owner (Address_To_Index (Ptr)) = Owner_Application
                 and then Len <= Buffer_Capacity,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Ptr)) = Owner_RX_Queue;

   procedure RX_Dequeue (Result : out Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if Result.Ptr = System.Null_Address
                       then True  --  Queue was empty
                       else Is_Valid_Buffer (Result.Ptr)
                            and Get_Owner (Address_To_Index (Result.Ptr))
                                = Owner_Application);

   procedure TX_Enqueue (Ptr : System.Address; Len : Natural)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved
                 and then Is_Valid_Buffer (Ptr)
                 and then Get_Owner (Address_To_Index (Ptr)) = Owner_Application
                 and then Len <= Buffer_Capacity,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Ptr)) = Owner_TX_Queue;

   procedure TX_Dequeue (Result : out Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if Result.Ptr = System.Null_Address
                       then True  --  Queue was empty
                       else Is_Valid_Buffer (Result.Ptr)
                            and Get_Owner (Address_To_Index (Result.Ptr))
                                = Owner_Application);

   ---------------------
   --  Ghost Ownership Predicates (for use in contracts)
   ---------------------

   function Is_Owned (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) = Owner_Application)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   function Is_In_RX_Queue (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) = Owner_RX_Queue)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   function Is_In_TX_Queue (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) = Owner_TX_Queue)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   ---------------------
   --  Statistics
   ---------------------

   function Free_Count return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => Free_Count'Result <= Pool_Size;

   function RX_Pending return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => RX_Pending'Result <= Pool_Size;

   function TX_Pending return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => TX_Pending'Result <= Pool_Size;

end Utils.Ring_Buffer;
