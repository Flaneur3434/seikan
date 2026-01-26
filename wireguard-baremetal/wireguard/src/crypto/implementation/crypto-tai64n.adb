--  TAI64N implementation using pure monotonic counter
--
--  No wall-clock dependency, no FFI, platform-independent.
--  Per WireGuard whitepaper: timestamps are soft-state, RAM-only.
--  Initial value is random to ensure fresh start after each boot.

with Crypto.Random;
with Utils; use Utils;

package body Crypto.TAI64N
  with SPARK_Mode => Off  --  Global counter state
is
   --  TAI64 base offset: 2^62 (TAI64 label)
   TAI64_Base : constant Unsigned_64 := 2 ** 62;

   --  Monotonic counter state (RAM only, resets on boot - this is OK)
   Counter_Seconds : Unsigned_64;
   Counter_Nanos   : Unsigned_32;

   procedure Now (T : out Timestamp) is
   begin
      --  Increment nanoseconds, handle overflow to seconds
      if Counter_Nanos < 999_999_999 then
         Counter_Nanos := Counter_Nanos + 1;
      else
         Counter_Nanos := 0;
         Counter_Seconds := Counter_Seconds + 1;
      end if;

      --  Encode TAI64 (8 bytes, big-endian / network order)
      T (0) := Unsigned_8 (Shift_Right (Counter_Seconds, 56) and 16#FF#);
      T (1) := Unsigned_8 (Shift_Right (Counter_Seconds, 48) and 16#FF#);
      T (2) := Unsigned_8 (Shift_Right (Counter_Seconds, 40) and 16#FF#);
      T (3) := Unsigned_8 (Shift_Right (Counter_Seconds, 32) and 16#FF#);
      T (4) := Unsigned_8 (Shift_Right (Counter_Seconds, 24) and 16#FF#);
      T (5) := Unsigned_8 (Shift_Right (Counter_Seconds, 16) and 16#FF#);
      T (6) := Unsigned_8 (Shift_Right (Counter_Seconds, 8) and 16#FF#);
      T (7) := Unsigned_8 (Counter_Seconds and 16#FF#);

      --  Encode nanoseconds (4 bytes, big-endian)
      T (8) := Unsigned_8 (Shift_Right (Counter_Nanos, 24) and 16#FF#);
      T (9) := Unsigned_8 (Shift_Right (Counter_Nanos, 16) and 16#FF#);
      T (10) := Unsigned_8 (Shift_Right (Counter_Nanos, 8) and 16#FF#);
      T (11) := Unsigned_8 (Counter_Nanos and 16#FF#);
   end Now;

   function Is_After (A, B : Timestamp) return Boolean is
   begin
      --  Ada array comparison is lexicographic (big-endian)
      return A > B;
   end Is_After;

   function Is_After_Or_Equal (A, B : Timestamp) return Boolean is
   begin
      return A >= B;
   end Is_After_Or_Equal;

begin
   --  Initialize counter with random seed at elaboration
   declare
      Random_Bytes : Byte_Array (0 .. 7);
   begin
      Crypto.Random.Fill_Random (Random_Bytes);

      Counter_Seconds :=
        TAI64_Base
        + Unsigned_64 (Random_Bytes (0))
        or Shift_Left (Unsigned_64 (Random_Bytes (1)), 8)
        or Shift_Left (Unsigned_64 (Random_Bytes (2)), 16)
        or Shift_Left (Unsigned_64 (Random_Bytes (3)), 24)
        or Shift_Left (Unsigned_64 (Random_Bytes (4)), 32)
        or Shift_Left (Unsigned_64 (Random_Bytes (5)), 40)
        or Shift_Left (Unsigned_64 (Random_Bytes (6)), 48)
        or Shift_Left (Unsigned_64 (Random_Bytes (7)), 56);

      Counter_Nanos := 0;
   end;
end Crypto.TAI64N;
