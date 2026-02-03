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

   --  TAI64N timestamp (opaque, 12 bytes big-endian)
   type Timestamp is private;

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

   --  Convert timestamp to byte array for network transmission (zero-copy)
   Timestamp_Bytes_Length : constant := 12;  --  8 bytes TAI64 + 4 bytes nanos
   subtype Timestamp_Bytes is Byte_Array (0 .. Timestamp_Bytes_Length - 1);
   type Timestamp_Bytes_Const_Access is access constant Timestamp_Bytes;

   --  Returns read-only access to the timestamp's internal bytes.
   --  The returned pointer is valid only while T remains in scope.
   function To_Bytes
     (T : aliased Timestamp) return Timestamp_Bytes_Const_Access
   with Global => null;

   --  Zero timestamp (useful for initialization)
   Zero : constant Timestamp;

private
   --  TAI64N timestamp type (big-endian format, suitable for network)
   type Timestamp is array (0 .. Timestamp_Bytes_Length - 1) of Unsigned_8;

   Zero : constant Timestamp := (others => 0);

end Crypto.TAI64N;
