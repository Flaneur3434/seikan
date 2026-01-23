--  Utils.Ring_Buffer - Pre-allocated buffer pool with SPARK ownership tracking
--
--  Provides a fixed pool of buffers for zero-copy packet handling.
--  Uses ghost state to formally track buffer ownership for SPARK proofs.
--
--  Ownership State Machine (ghost state - proof only, no runtime cost):
--    Free          : Available for allocation in the pool
--    C_RxFill      : Owned by C, receiving data via recvfrom
--    RxQ           : Queued for Ada to process
--    Ada_RxProcess : Owned by Ada during RX packet processing
--    Ada_TxBuild   : Owned by Ada while building TX packet
--    Ada_TxEncrypt : Owned by Ada during in-place encryption
--    TxQ           : Queued for C to send
--    C_TxSend      : Owned by C during sendto (may retry on EAGAIN)
--
--  Valid Transitions:
--    RX path: Free -> C_RxFill -> RxQ -> Ada_RxProcess -> Free
--    TX path: Free -> Ada_TxBuild -> Ada_TxEncrypt -> TxQ -> C_TxSend -> Free
--
--  DESIGN:
--    - Buffers are pre-allocated at elaboration (no malloc in hot path)
--    - Ghost tokens verify ownership protocol at compile time
--    - Single owner invariant: exactly one owner at all times
--    - Alignment: 16 bytes for optimal SIMD/DMA operations
--
--  C Interface:
--    wg_buf_init()           - Initialize buffer pool
--    wg_buf_rx_alloc()       - Allocate for RX (Free -> C_RxFill)
--    wg_buf_rx_enqueue(p,l)  - Enqueue RX buffer (C_RxFill -> RxQ)
--    wg_buf_tx_dequeue(&d)   - Dequeue TX buffer (TxQ -> C_TxSend)
--    wg_buf_tx_complete(p)   - Complete TX send (C_TxSend -> Free)
--    wg_buf_capacity()       - Get buffer capacity (1560 bytes)
--    wg_buf_free_count()     - Get number of available buffers

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

   Buffer_Capacity : constant := 1560;  --  MTU (1500) + headers + tag
   Pool_Size       : constant := 16;    --  Number of buffers
   Buffer_Alignment : constant := 16;   --  16-byte alignment

   subtype Buffer_Index is Natural range 0 .. Pool_Size - 1;
   subtype Buffer_Count is Natural range 0 .. Pool_Size;

   --  Unique buffer identifier for ghost modeling
   type Buffer_Id is new Natural range 0 .. Pool_Size - 1;

   ---------------------
   --  Ownership State Machine (Ghost Types - proof only, no runtime cost)
   ---------------------

   --  All possible ownership states matching the zero-copy protocol
   type Owner_State is (
      Free,           --  In pool, available for allocation
      C_RxFill,       --  C owns: receiving into buffer via recvfrom
      RxQ,            --  Queued: waiting for Ada to process
      Ada_RxProcess,  --  Ada owns: processing received packet
      Ada_TxBuild,    --  Ada owns: building TX packet plaintext
      Ada_TxEncrypt,  --  Ada owns: performing in-place encryption
      TxQ,            --  Queued: waiting for C to send
      C_TxSend        --  C owns: sending via sendto (may EAGAIN)
   ) with Ghost;

   type Ownership_Array is array (Buffer_Index) of Owner_State
     with Ghost;

   ---------------------
   --  Ghost State Queries
   ---------------------

   function Get_Owner (Index : Buffer_Index) return Owner_State
     with Ghost,
          Global => (Input => Ghost_Ownership);

   function Count_In_State (State : Owner_State) return Buffer_Count
     with Ghost,
          Global => (Input => Ghost_Ownership);

   --  Conservation invariant: all buffers are always accounted for
   function Ownership_Conserved return Boolean
     with Ghost,
          Global => (Input => Ghost_Ownership);

   ---------------------
   --  State Transition Predicates (Ghost)
   ---------------------

   --  Valid RX path transitions
   function Is_Valid_Rx_Alloc_Transition (From : Owner_State) return Boolean is
     (From = Free)
     with Ghost;

   function Is_Valid_Rx_Enqueue_Transition (From : Owner_State) return Boolean is
     (From = C_RxFill)
     with Ghost;

   function Is_Valid_Rx_Dequeue_Transition (From : Owner_State) return Boolean is
     (From = RxQ)
     with Ghost;

   function Is_Valid_Rx_Complete_Transition (From : Owner_State) return Boolean is
     (From = Ada_RxProcess)
     with Ghost;

   --  Valid TX path transitions
   function Is_Valid_Tx_Alloc_Transition (From : Owner_State) return Boolean is
     (From = Free)
     with Ghost;

   function Is_Valid_Tx_Ready_Transition (From : Owner_State) return Boolean is
     (From = Ada_TxBuild)
     with Ghost;

   function Is_Valid_Tx_Enqueue_Transition (From : Owner_State) return Boolean is
     (From = Ada_TxEncrypt)
     with Ghost;

   function Is_Valid_Tx_Dequeue_Transition (From : Owner_State) return Boolean is
     (From = TxQ)
     with Ghost;

   function Is_Valid_Tx_Complete_Transition (From : Owner_State) return Boolean is
     (From = C_TxSend)
     with Ghost;

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

   function Get_Buffer_Id (Index : Buffer_Index) return Buffer_Id is
     (Buffer_Id (Index))
     with Ghost;

   ---------------------
   --  Buffer Descriptor (C-compatible, for passing to queues)
   ---------------------

   type Buffer_Descriptor is record
      Ptr : System.Address;  --  Pointer to buffer data
      Len : size_t;          --  Actual data length in buffer
      Cap : size_t;          --  Buffer capacity
      Id  : size_t;          --  Buffer ID for ghost modeling
   end record
     with Convention => C;

   Null_Descriptor : constant Buffer_Descriptor :=
     (Ptr => System.Null_Address, Len => 0, Cap => 0, Id => 0);

   ---------------------
   --  Pool Initialization
   ---------------------

   procedure Initialize
     with Global => (Output => (Buffer_Pool_State, Ghost_Ownership)),
          Post => (for all I in Buffer_Index => Get_Owner (I) = Free)
                  and Count_In_State (Free) = Pool_Size
                  and Ownership_Conserved;

   ---------------------
   --  RX Path Operations
   ---------------------

   --  Allocate a buffer for RX (C calls this before recvfrom)
   --  Transition: Free -> C_RxFill
   procedure Rx_Alloc (Desc : out Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if Desc.Ptr = System.Null_Address
                       then Count_In_State (Free) = 0
                       else Is_Valid_Buffer (Desc.Ptr)
                            and Get_Owner (Address_To_Index (Desc.Ptr)) = C_RxFill
                            and Desc.Cap = size_t (Buffer_Capacity)
                            and Desc.Len = 0);

   --  Enqueue filled RX buffer (C calls after recvfrom success)
   --  Transition: C_RxFill -> RxQ
   procedure Rx_Enqueue (Desc : Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and then Desc.Ptr /= System.Null_Address
                  and then Is_Valid_Buffer (Desc.Ptr)
                  and then Get_Owner (Address_To_Index (Desc.Ptr)) = C_RxFill,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Desc.Ptr)) = RxQ;

   --  Dequeue RX buffer for processing (Ada calls this)
   --  Transition: RxQ -> Ada_RxProcess
   procedure Rx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if not Success
                       then Desc = Null_Descriptor
                       else Is_Valid_Buffer (Desc.Ptr)
                            and Get_Owner (Address_To_Index (Desc.Ptr))
                                = Ada_RxProcess);

   --  Complete RX processing, return buffer to pool (Ada calls this)
   --  Transition: Ada_RxProcess -> Free
   procedure Rx_Complete (Ptr : System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and then Ptr /= System.Null_Address
                  and then Is_Valid_Buffer (Ptr)
                  and then Get_Owner (Address_To_Index (Ptr)) = Ada_RxProcess,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Ptr)) = Free;

   ---------------------
   --  TX Path Operations
   ---------------------

   --  Allocate a buffer for TX (Ada calls this)
   --  Transition: Free -> Ada_TxBuild
   procedure Tx_Alloc (Desc : out Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if Desc.Ptr = System.Null_Address
                       then Count_In_State (Free) = 0
                       else Is_Valid_Buffer (Desc.Ptr)
                            and Get_Owner (Address_To_Index (Desc.Ptr)) = Ada_TxBuild
                            and Desc.Cap = size_t (Buffer_Capacity)
                            and Desc.Len = 0);

   --  Mark buffer as ready for encryption (Ada calls this)
   --  Transition: Ada_TxBuild -> Ada_TxEncrypt
   procedure Tx_Ready (Ptr : System.Address; Len : size_t)
     with Global => (Input  => Buffer_Pool_State,
                     In_Out => Ghost_Ownership),
          Pre  => Ownership_Conserved
                  and then Ptr /= System.Null_Address
                  and then Is_Valid_Buffer (Ptr)
                  and then Get_Owner (Address_To_Index (Ptr)) = Ada_TxBuild,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Ptr)) = Ada_TxEncrypt;

   --  Enqueue encrypted TX buffer for sending (Ada calls after encryption)
   --  Transition: Ada_TxEncrypt -> TxQ
   procedure Tx_Enqueue (Desc : Buffer_Descriptor)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and then Desc.Ptr /= System.Null_Address
                  and then Is_Valid_Buffer (Desc.Ptr)
                  and then Get_Owner (Address_To_Index (Desc.Ptr)) = Ada_TxEncrypt,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Desc.Ptr)) = TxQ;

   --  Dequeue TX buffer for sending (C calls this)
   --  Transition: TxQ -> C_TxSend
   procedure Tx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved,
          Post => Ownership_Conserved
                  and (if not Success
                       then Desc = Null_Descriptor
                       else Is_Valid_Buffer (Desc.Ptr)
                            and Get_Owner (Address_To_Index (Desc.Ptr))
                                = C_TxSend);

   --  Complete TX send, return buffer to pool (C calls after sendto success)
   --  Transition: C_TxSend -> Free
   procedure Tx_Complete (Ptr : System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and then Ptr /= System.Null_Address
                  and then Is_Valid_Buffer (Ptr)
                  and then Get_Owner (Address_To_Index (Ptr)) = C_TxSend,
          Post => Ownership_Conserved
                  and then Get_Owner (Address_To_Index (Ptr)) = Free;

   ---------------------
   --  Drop/Abort Operations (for error paths)
   ---------------------

   --  Drop an RX buffer at any point in RX path
   procedure Rx_Drop (Ptr : System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and (Ptr = System.Null_Address
                       or else (Is_Valid_Buffer (Ptr)
                                and then Get_Owner (Address_To_Index (Ptr))
                                         in C_RxFill | RxQ | Ada_RxProcess)),
          Post => Ownership_Conserved
                  and (if Ptr /= System.Null_Address and Is_Valid_Buffer (Ptr)
                       then Get_Owner (Address_To_Index (Ptr)) = Free);

   --  Drop a TX buffer at any point in TX path
   procedure Tx_Drop (Ptr : System.Address)
     with Global => (In_Out => (Buffer_Pool_State, Ghost_Ownership)),
          Pre  => Ownership_Conserved
                  and (Ptr = System.Null_Address
                       or else (Is_Valid_Buffer (Ptr)
                                and then Get_Owner (Address_To_Index (Ptr))
                                         in Ada_TxBuild | Ada_TxEncrypt | TxQ | C_TxSend)),
          Post => Ownership_Conserved
                  and (if Ptr /= System.Null_Address and Is_Valid_Buffer (Ptr)
                       then Get_Owner (Address_To_Index (Ptr)) = Free);

   ---------------------
   --  Ghost Ownership Predicates (for use in contracts)
   ---------------------

   --  Check if buffer is in Free state
   function Is_Free (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) = Free)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   --  Check if buffer is owned by C (RX or TX paths)
   function Is_C_Owned (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) in C_RxFill | C_TxSend)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   --  Check if buffer is owned by Ada (RX or TX paths)
   function Is_Ada_Owned (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr))
               in Ada_RxProcess | Ada_TxBuild | Ada_TxEncrypt)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   --  Check if buffer is in any queue
   function Is_Queued (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr)) in RxQ | TxQ)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   --  Check if buffer is in RX path (any RX state)
   function Is_In_Rx_Path (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr))
               in C_RxFill | RxQ | Ada_RxProcess)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   --  Check if buffer is in TX path (any TX state)
   function Is_In_Tx_Path (Ptr : System.Address) return Boolean is
     (Is_Valid_Buffer (Ptr)
      and then Get_Owner (Address_To_Index (Ptr))
               in Ada_TxBuild | Ada_TxEncrypt | TxQ | C_TxSend)
     with Ghost,
          Global => (Input => (Buffer_Pool_State, Ghost_Ownership));

   ---------------------
   --  Statistics
   ---------------------

   function Free_Count return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => Free_Count'Result <= Pool_Size;

   function Rx_Queue_Count return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => Rx_Queue_Count'Result <= Pool_Size;

   function Tx_Queue_Count return Natural
     with Global => (Input => Buffer_Pool_State),
          Post => Tx_Queue_Count'Result <= Pool_Size;

end Utils.Ring_Buffer;
