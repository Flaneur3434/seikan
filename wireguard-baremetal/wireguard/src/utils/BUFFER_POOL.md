# Utils.Memory_Pool - SPARK Ownership-Tracked Buffer Pool

Zero-copy buffer management with **SPARK ownership semantics**.
Uses GNATprove's `Ownership` annotation to enforce move semantics
and prevent aliasing at the call site, while the implementation
uses efficient access types internally.

## Design Philosophy

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SPARK Boundary                              │
│                                                                     │
│   Buffer_Handle (private type with Ownership annotation)            │
│     - Move semantics enforced by SPARK                              │
│     - No aliasing possible                                          │
│     - Must be freed before scope ends (Needs_Reclamation)           │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                    Implementation (SPARK_Mode => Off)               │
│                                                                     │
│   Buffer_Handle = access all Packet_Buffer                          │
│     - Direct pointer to static buffer array                         │
│     - Zero-copy: no data movement                                   │
│     - O(1) allocate/free via stack                                  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Configuration

```ada
generic
   Packet_Size : Positive;  -- e.g., 1560 (MTU + crypto overhead)
   Pool_Size   : Positive;  -- e.g., 8 buffers
package Utils.Memory_Pool
```

## SPARK Ownership Model

The key insight: **hide the access type behind a private type with ownership annotations**.

```ada
type Buffer_Handle is private
  with Default_Initial_Condition => Is_Null (Buffer_Handle),
       Annotate => (GNATprove, Ownership, "Needs_Reclamation");

function Is_Null (H : Buffer_Handle) return Boolean
  with Annotate => (GNATprove, Ownership, "Is_Reclaimed");
```

### What SPARK Enforces

1. **Move Semantics**: Assignment moves ownership, source becomes invalid
   ```ada
   H1 : Buffer_Handle;
   H2 : Buffer_Handle;
   
   Allocate (H1);
   H2 := H1;      -- H1 is now INVALID (moved)
   Free (H2);     -- OK
   Free (H1);     -- SPARK ERROR: H1 was moved
   ```

2. **No Aliasing**: Can't have two valid handles to same buffer
   ```ada
   H1 : Buffer_Handle;
   H2 : Buffer_Handle;
   
   Allocate (H1);
   H2 := H1;           -- Move, not copy
   -- Both H1 and H2 pointing to same buffer? IMPOSSIBLE
   ```

3. **No Leaks**: Must free or move before scope ends
   ```ada
   procedure Leaky is
      H : Buffer_Handle;
   begin
      Allocate (H);
      -- SPARK ERROR: H not freed before end of scope
   end Leaky;
   ```

## API

### Pool Operations

```ada
procedure Initialize
  with Post => Free_Count = Pool_Size;
--  Initialize pool. Call once at startup.

procedure Allocate (Handle : out Buffer_Handle)
  with Post => (if not Is_Null (Handle)
                then Free_Count = Free_Count'Old - 1
                else Free_Count = Free_Count'Old);
--  Get a buffer. Handle is null if pool exhausted.

procedure Free (Handle : in out Buffer_Handle)
  with Pre  => not Is_Null (Handle),
       Post => Is_Null (Handle)
               and then Free_Count = Free_Count'Old + 1;
--  Return buffer to pool. Clears sensitive data.
```

### Buffer Access (Zero-Copy)

```ada
function Data (Handle : Buffer_Handle) return System.Address
  with Pre => not Is_Null (Handle);
--  Get raw address for direct read/write.
--  WARNING: Address only valid while Handle is valid.
```

### C FFI

```ada
function C_Allocate return System.Address;
--  Returns buffer address, or Null_Address if exhausted

procedure C_Free (Addr : System.Address);
--  Free by address. Safe with Null_Address.
```

## Implementation Details

### Internal State

```ada
--  Static buffer array (no heap allocation)
Buffers : array (Pool_Index) of aliased Packet_Buffer;

--  LIFO stack of free indices for O(1) alloc/free
Free_Stack : array (Pool_Index) of Pool_Index;
Free_Top   : Integer := -1;  -- -1 = empty
```

### Allocate

```ada
procedure Allocate (Handle : out Buffer_Handle) is
begin
   if Free_Top < 0 then
      Handle := null;  -- Pool exhausted
   else
      Handle := Buffers (Free_Stack (Free_Top))'Access;
      Free_Top := Free_Top - 1;
   end if;
end Allocate;
```

### Free

```ada
procedure Free (Handle : in out Buffer_Handle) is
begin
   --  Find index by address comparison
   for I in Pool_Index loop
      if Buffers (I)'Address = Handle.all'Address then
         Handle.all := (others => 0);  -- Clear sensitive data
         Handle := null;
         Free_Top := Free_Top + 1;
         Free_Stack (Free_Top) := I;
         return;
      end if;
   end loop;
end Free;
```

## Usage Examples

### Ada (SPARK-verified)

```ada
procedure Process_Packet is
   H : Buffer_Handle;
begin
   Allocate (H);
   if not Is_Null (H) then
      declare
         Addr : constant System.Address := Data (H);
         --  Use Addr for zero-copy operations...
      begin
         null;
      end;
      Free (H);  -- REQUIRED by SPARK
   end if;
end Process_Packet;
```

### C (via FFI)

```c
void* buf = packet_pool_allocate();
if (buf != NULL) {
    // Direct memory access
    memcpy(buf, incoming_data, len);
    
    // Process...
    
    packet_pool_free(buf);
}
```

## SPARK Verification Results

```
SPARK Analysis results        Total      Flow      Provers
─────────────────────────────────────────────────────────
Run-time Checks                  10         .    10 (CVC5)
Termination                       1         1            .
─────────────────────────────────────────────────────────
Total                            11    1 (9%)     10 (91%)
```

### What's Verified

| Property | Verification |
|----------|--------------|
| No buffer leaks | Ownership annotation |
| No aliasing | Move semantics |
| No double-free | Pre: not Is_Null |
| No use-after-free | Handle invalidated |
| Bounds safety | Array index checks |

### What's Trusted (SPARK_Mode => Off)

- Access type implementation
- Address arithmetic in `Data`
- C FFI functions

## Comparison with Alternatives

| Approach | Zero-Copy | SPARK Verified | Complexity |
|----------|-----------|----------------|------------|
| Index-based | ❌ (copies via Get/Set) | ✅ Full | Low |
| Named access types | ✅ | ❌ (ownership issues) | Medium |
| **Private + Ownership** | ✅ | ✅ Partial | Low |
| Anonymous access | ✅ | ❌ (can't return) | High |

## Security Properties

1. **Buffer clearing**: `Free` zeros buffer content before returning to pool
2. **No dangling pointers**: Handle becomes null after free
3. **Bounded memory**: Static allocation, no heap fragmentation
4. **Alignment**: 16-byte aligned for DMA/SIMD operations
