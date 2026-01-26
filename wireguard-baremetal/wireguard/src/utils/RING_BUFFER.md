# Ring Buffer Module

Pre-allocated buffer pool for zero-copy packet handling with provable ownership protocol.

## Design Overview

The ring buffer implements a **boundary ownership token** model where every buffer is in exactly one ownership state at any time. Ghost state (proof-only, no runtime cost) formally tracks ownership for SPARK proofs.

**Key Design Principle**: Minimize raw pointer usage. Ada code uses typed `Buffer` handles with `Buffer_Data_Ptr` (typed access to constrained arrays), while raw `System.Address` is only used at the C interface boundary.

## Ownership State Machine

```
                    RX PATH                          TX PATH
                    ───────                          ───────

                   ┌─────────┐
                   │  Free   │◄────────────────────────────────────┐
                   └────┬────┘                                     │
         Rx_Alloc()     │             Tx_Alloc()                   │
                   ┌────▼────┐                    ┌───────────┐    │
                   │C_RxFill │                    │Ada_TxBuild│ ◄──┤
                   └────┬────┘                    └─────┬─────┘    │
         Rx_Enqueue()   │             Tx_Ready()        │          │
                   ┌────▼────┐                    ┌─────▼───────┐  │
                   │   RxQ   │                    │Ada_TxEncrypt│  │
                   └────┬────┘                    └─────┬───────┘  │
         Rx_Dequeue()   │             Tx_Enqueue()      │          │
                   ┌────▼────────┐                ┌─────▼────┐     │
                   │Ada_RxProcess│                │   TxQ    │     │
                   └────┬────────┘                └─────┬────┘     │
         Rx_Complete()  │             Tx_Dequeue()      │          │
                        │                         ┌─────▼────┐     │
                        │                         │ C_TxSend │     │
                        │                         └─────┬────┘     │
                        │             Tx_Complete()     │          │
                        └───────────────────────────────┴──────────┘
```

### State Descriptions

| State | Owner | Description |
|-------|-------|-------------|
| `Free` | Pool | Available for allocation |
| `C_RxFill` | C | C receiving data via recvfrom |
| `RxQ` | Queue | Waiting for Ada to process |
| `Ada_RxProcess` | Ada | Ada processing received packet |
| `Ada_TxBuild` | Ada | Ada building TX packet plaintext |
| `Ada_TxEncrypt` | Ada | Ada performing in-place AEAD encryption |
| `TxQ` | Queue | Waiting for C to send |
| `C_TxSend` | C | C sending via sendto (may EAGAIN) |

## Valid Transitions

**RX Path:**
```
Free → C_RxFill → RxQ → Ada_RxProcess → Free
```

**TX Path:**
```
Free → Ada_TxBuild → Ada_TxEncrypt → TxQ → C_TxSend → Free
```

**Drop Paths (error handling):**
```
C_RxFill | RxQ | Ada_RxProcess → Free  (via Rx_Drop)
Ada_TxBuild | Ada_TxEncrypt | TxQ | C_TxSend → Free  (via Tx_Drop)
```

## Buffer Types

### Buffer (Ada-friendly handle)

The primary type for Ada code. Uses a typed pointer instead of raw addresses:

```ada
--  Fixed-size buffer data array
subtype Buffer_Data is Byte_Array (0 .. Buffer_Capacity - 1);

--  Typed pointer (thin pointer, C-compatible)
--  Using 'access all' allows pointing to statically-allocated buffers
type Buffer_Data_Ptr is access all Buffer_Data with Convention => C;

--  Ada buffer handle - passed by reference for large records
type Buffer is record
   Data : Buffer_Data_Ptr;  -- Typed pointer to buffer data
   Len  : Natural;          -- Actual data length
   Id   : Buffer_Index;     -- Buffer ID for ownership tracking
end record;
```

**Benefits:**
- **Type safety**: `Buffer_Data_Ptr` can only point to correctly-sized arrays
- **Native array access**: `Buf.Data.all (I)` or `Buf.Data (Start .. End)` with bounds checking
- **No raw pointers in Ada**: Only the C interface uses `System.Address`
- **Pass by reference**: Ada automatically passes large records by reference

### Buffer_Descriptor (C interface only)

Raw pointer-based struct for C interop:

```ada
type Buffer_Descriptor is record
   Ptr : System.Address;  -- Raw pointer for C code
   Len : size_t;          -- Actual data length
   Cap : size_t;          -- Buffer capacity (1560)
   Id  : size_t;          -- Buffer ID for ghost modeling
end record with Convention => C;
```

Conversion functions:
```ada
function To_Descriptor (B : Buffer) return Buffer_Descriptor;
function From_Descriptor (D : Buffer_Descriptor) return Buffer;
```

## Configuration

- **Buffer_Capacity**: 1560 bytes (MTU 1500 + headers + Poly1305 tag)
- **Pool_Size**: 16 buffers
- **Buffer_Alignment**: 16 bytes (optimal for SIMD/DMA)

## Ada API

### Initialization

```ada
procedure Initialize;
--  Post: all buffers in Free state
```

### RX Path Operations

```ada
procedure Rx_Alloc (Buf : out Buffer);
--  Transition: Free → C_RxFill
--  Returns Null_Buffer if pool exhausted

procedure Rx_Enqueue (Buf : Buffer);
--  Transition: C_RxFill → RxQ
--  Pre: buffer in C_RxFill state

procedure Rx_Dequeue (Buf : out Buffer; Success : out Boolean);
--  Transition: RxQ → Ada_RxProcess
--  Returns Success=False if queue empty

procedure Rx_Complete (Buf : in out Buffer);
--  Transition: Ada_RxProcess → Free
--  Pre: buffer in Ada_RxProcess state
--  Post: Buf is invalidated (set to Null_Buffer)

procedure Rx_Drop (Buf : in out Buffer);
--  Transition: any RX state → Free
--  For error handling/cleanup
--  Post: Buf is invalidated
```

### TX Path Operations

```ada
procedure Tx_Alloc (Buf : out Buffer);
--  Transition: Free → Ada_TxBuild
--  Returns Null_Buffer if pool exhausted

procedure Tx_Ready (Buf : in out Buffer; Len : Natural);
--  Transition: Ada_TxBuild → Ada_TxEncrypt
--  Call after writing plaintext, before encryption
--  Updates Buf.Len to Len

procedure Tx_Enqueue (Buf : Buffer);
--  Transition: Ada_TxEncrypt → TxQ
--  Call after encryption complete

procedure Tx_Dequeue (Buf : out Buffer; Success : out Boolean);
--  Transition: TxQ → C_TxSend
--  Returns Success=False if queue empty

procedure Tx_Complete (Buf : in out Buffer);
--  Transition: C_TxSend → Free
--  Pre: buffer in C_TxSend state
--  Post: Buf is invalidated

procedure Tx_Drop (Buf : in out Buffer);
--  Transition: any TX state → Free
--  For error handling/cleanup
--  Post: Buf is invalidated
```

### Buffer Access

```ada
--  Check if buffer is valid
function Is_Valid (B : Buffer) return Boolean is (B.Data /= null);

--  Get buffer capacity
function Capacity (B : Buffer) return Natural;  -- Returns Buffer_Capacity or 0

--  Access buffer data (type-safe, bounds-checked)
Buf.Data.all (Index)           -- Single element access
Buf.Data (Start .. End)        -- Slice access
Buf.Data.all                   -- Full array access
```

### Statistics

```ada
function Free_Count return Natural;     -- Buffers in Free state
function Rx_Queue_Count return Natural; -- Buffers in RxQ state
function Tx_Queue_Count return Natural; -- Buffers in TxQ state
```

## C Interface

```c
// Initialization
void wg_buf_init(void);

// RX Path
Buffer_Descriptor wg_buf_rx_alloc(void);      // Free → C_RxFill
void wg_buf_rx_enqueue(Buffer_Descriptor d);  // C_RxFill → RxQ

// TX Path
int wg_buf_tx_dequeue(Buffer_Descriptor* d);  // TxQ → C_TxSend (returns 1/0)
void wg_buf_tx_complete(void* ptr);           // C_TxSend → Free

// Statistics
size_t wg_buf_capacity(void);      // Buffer size (1560)
size_t wg_buf_free_count(void);    // Free buffers
size_t wg_buf_rx_queue_count(void);// RX queue depth
size_t wg_buf_tx_queue_count(void);// TX queue depth
```

## Ghost Ownership Model

Ghost state provides compile-time verification of ownership invariants:

### Key Invariants

1. **Single Owner**: No buffer is in two states simultaneously
2. **Conservation**: Total buffers across all states = Pool_Size
3. **Legal Transitions**: Only valid state edges are possible
4. **No Double Free**: Free state only reachable via valid completion/drop

### Ghost Predicates

```ada
function Is_Free (B : Buffer) return Boolean;      -- In Free state
function Is_C_Owned (B : Buffer) return Boolean;   -- In C_RxFill or C_TxSend
function Is_Ada_Owned (B : Buffer) return Boolean; -- In Ada_RxProcess/TxBuild/TxEncrypt
function Is_Queued (B : Buffer) return Boolean;    -- In RxQ or TxQ
function Is_In_Rx_Path (B : Buffer) return Boolean;-- Any RX state
function Is_In_Tx_Path (B : Buffer) return Boolean;-- Any TX state
```

## Usage Flow Examples

### RX Path (C → Ada)

```c
// C networking layer
Buffer_Descriptor desc = wg_buf_rx_alloc();
if (desc.ptr == NULL) return;  // backpressure

ssize_t n = recvfrom(fd, desc.ptr, desc.cap, ...);
if (n > 0) {
    desc.len = n;
    wg_buf_rx_enqueue(desc);  // hand to Ada
}
// after enqueue, C cannot touch buffer
```

```ada
-- Ada WireGuard core
Rx_Dequeue (Buf, Success);
if Success then
   --  Access packet data directly via typed pointer
   Process_Packet (Buf.Data (0 .. Buf.Len - 1));
   Rx_Complete (Buf);  -- return to pool, Buf invalidated
end if;
```

### TX Path (Ada → C)

```ada
-- Ada WireGuard core
Tx_Alloc (Buf);
if Is_Valid (Buf) then
   --  Write header + plaintext directly to buffer
   Buf.Data (0 .. Header_Len - 1) := Header;
   Buf.Data (Header_Len .. Header_Len + Payload_Len - 1) := Payload;
   
   Tx_Ready (Buf, Header_Len + Payload_Len);
   
   --  Encrypt in-place (header as AAD, payload encrypted)
   Encrypt_In_Place (Buf.Data.all, Payload_Len, Nonce, Key, Status);
   Buf.Len := Final_Packet_Length;
   
   Tx_Enqueue (Buf);  -- hand to C
end if;
```

```c
// C networking layer
Buffer_Descriptor desc;
if (wg_buf_tx_dequeue(&desc)) {
    ssize_t n = sendto(fd, desc.ptr, desc.len, ...);
    if (n == desc.len) {
        wg_buf_tx_complete(desc.ptr);  // return to pool
    } else if (errno == EAGAIN) {
        // keep in C_TxSend, retry later
    }
}
```

## Backpressure Handling

- **RX exhaustion**: `Rx_Alloc` returns null descriptor; C should not call recvfrom
- **TX EAGAIN**: Buffer stays in `C_TxSend` state; C retries sendto later
- **Queue full**: Not directly possible with current design (bounded by pool size)

## Thread Safety

The current implementation is **NOT thread-safe**. For multi-threaded use:
- Use platform-specific queues (FreeRTOS xQueue) for actual inter-task communication
- Ada-side operations should be called from a single task
- C-side operations should be called from a single task

The internal RX/TX queues are for demonstration; production code should use FreeRTOS queues that only copy the 32-byte `Buffer_Descriptor`, not buffer data.

## Why `access all` instead of `access`?

The `Buffer_Data_Ptr` type uses `access all` because:

- **`access T`** - Can only point to heap-allocated objects (created with `new`)
- **`access all T`** - Can point to *any* aliased object, including statically-allocated ones

Our buffer pool is **pre-allocated statically** (not heap-allocated), so we need `access all` to take `'Access` of the statically-allocated `Buffers` array elements.
