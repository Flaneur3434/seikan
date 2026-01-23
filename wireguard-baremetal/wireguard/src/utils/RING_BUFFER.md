# Ring Buffer Module

Pre-allocated buffer pool for zero-copy packet handling with provable ownership protocol.

## Design Overview

The ring buffer implements a **boundary ownership token** model where every buffer is in exactly one ownership state at any time. Ghost state (proof-only, no runtime cost) formally tracks ownership for SPARK proofs.

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

## Buffer Descriptor

```ada
type Buffer_Descriptor is record
   Ptr : System.Address;  -- Pointer to buffer data
   Len : size_t;          -- Actual data length
   Cap : size_t;          -- Buffer capacity (1560)
   Id  : size_t;          -- Buffer ID for ghost modeling
end record with Convention => C;
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
procedure Rx_Alloc (Desc : out Buffer_Descriptor);
--  Transition: Free → C_RxFill
--  Returns Null_Descriptor if pool exhausted

procedure Rx_Enqueue (Desc : Buffer_Descriptor);
--  Transition: C_RxFill → RxQ
--  Pre: buffer in C_RxFill state

procedure Rx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean);
--  Transition: RxQ → Ada_RxProcess
--  Returns Success=False if queue empty

procedure Rx_Complete (Ptr : System.Address);
--  Transition: Ada_RxProcess → Free
--  Pre: buffer in Ada_RxProcess state

procedure Rx_Drop (Ptr : System.Address);
--  Transition: any RX state → Free
--  For error handling/cleanup
```

### TX Path Operations

```ada
procedure Tx_Alloc (Desc : out Buffer_Descriptor);
--  Transition: Free → Ada_TxBuild
--  Returns Null_Descriptor if pool exhausted

procedure Tx_Ready (Ptr : System.Address; Len : size_t);
--  Transition: Ada_TxBuild → Ada_TxEncrypt
--  Call after writing plaintext, before encryption

procedure Tx_Enqueue (Desc : Buffer_Descriptor);
--  Transition: Ada_TxEncrypt → TxQ
--  Call after encryption complete

procedure Tx_Dequeue (Desc : out Buffer_Descriptor; Success : out Boolean);
--  Transition: TxQ → C_TxSend
--  Returns Success=False if queue empty

procedure Tx_Complete (Ptr : System.Address);
--  Transition: C_TxSend → Free
--  Pre: buffer in C_TxSend state

procedure Tx_Drop (Ptr : System.Address);
--  Transition: any TX state → Free
--  For error handling/cleanup
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
function Is_Free (Ptr) return Boolean;      -- In Free state
function Is_C_Owned (Ptr) return Boolean;   -- In C_RxFill or C_TxSend
function Is_Ada_Owned (Ptr) return Boolean; -- In Ada_RxProcess/TxBuild/TxEncrypt
function Is_Queued (Ptr) return Boolean;    -- In RxQ or TxQ
function Is_In_Rx_Path (Ptr) return Boolean;-- Any RX state
function Is_In_Tx_Path (Ptr) return Boolean;-- Any TX state
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
Rx_Dequeue (Desc, Success);
if Success then
   --  Process packet via Const_Span over Desc.Ptr/Desc.Len
   Process_Packet (Desc);
   Rx_Complete (Desc.Ptr);  -- return to pool
end if;
```

### TX Path (Ada → C)

```ada
-- Ada WireGuard core
Tx_Alloc (Desc);
if Desc.Ptr /= Null_Address then
   --  Write header + plaintext via Mut_Span
   Build_Packet (Desc);
   Tx_Ready (Desc.Ptr, Plaintext_Len);
   
   --  Encrypt in-place (header as AAD, payload encrypted)
   Encrypt_In_Place (Desc);
   Desc.Len := Final_Packet_Length;
   
   Tx_Enqueue (Desc);  -- hand to C
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
