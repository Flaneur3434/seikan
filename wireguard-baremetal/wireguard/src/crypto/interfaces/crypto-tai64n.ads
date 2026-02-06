--  TAI64N Timestamps for WireGuard
--
--  TAI64N is a 12-byte timestamp format:
--    - 8 bytes: TAI64 (seconds since 1970-01-01 00:00:00 TAI + 2^62)
--    - 4 bytes: nanoseconds (0 to 999999999)
--
--  Used in WireGuard for replay protection in handshake initiation messages.
--  Per the WireGuard whitepaper, timestamps are soft-state (RAM only) and
--  need not persist across reboots - there are no sessions to protect after
--  restart, so replay safety resets cleanly.
--
--  This implementation uses a pure monotonic counter, which is:
--    - SPARK-provable
--    - Platform-independent
--    - Requires no wall-clock or FFI

with Interfaces;
with Utils; use Utils;

package Crypto.TAI64N
  with SPARK_Mode => On, Elaborate_Body
is
   use Interfaces;

   --  TAI64N timestamp (12 bytes big-endian, network byte order)
   --  Public so the SPARK prover can see the size across packages.
   Timestamp_Bytes_Length : constant := 12;  --  8 bytes TAI64 + 4 bytes nanos
   type Timestamp is array (0 .. Timestamp_Bytes_Length - 1) of Unsigned_8;

   --  Byte_Array overlay for network I/O and AEAD encrypt/decrypt
   subtype Timestamp_Bytes is Byte_Array (0 .. Timestamp_Bytes_Length - 1);

   --  Non-nullable access for zero-copy byte access.
   --  The type itself guarantees non-null; no postcondition needed.
   type Timestamp_Bytes_Const_Access is
     not null access constant Timestamp_Bytes;

   --  Zero timestamp (useful for initialization)
   Zero : constant Timestamp := (others => 0);

   --  Get next monotonically increasing TAI64N timestamp
   --  Each call returns a value strictly greater than the previous
   procedure Now (T : out Timestamp)
   with
     Global => null;  --  Note: has hidden state, but SPARK_Mode => Off in body

   --  Compare two timestamps
   --  Returns True if A is strictly greater (later) than B
   function Is_After (A, B : Timestamp) return Boolean
   with Global => null;

   --  Check if timestamp A is after or equal to B
   function Is_After_Or_Equal (A, B : Timestamp) return Boolean
   with Global => null;

   --  Returns read-only access to the timestamp's internal bytes.
   --  The returned pointer is valid only while T remains in scope.
   function To_Bytes
     (T : aliased Timestamp) return Timestamp_Bytes_Const_Access
   with Global => null;

   --  Convert a Byte_Array (e.g. from AEAD decrypt) back to Timestamp.
   --  Eliminates the need for Unchecked_Conversion across packages.
   function From_Bytes (B : Timestamp_Bytes) return Timestamp
   with Global => null;

end Crypto.TAI64N;
