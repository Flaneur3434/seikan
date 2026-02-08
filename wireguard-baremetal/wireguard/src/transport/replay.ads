--  Replay - Anti-Replay Sliding Window
--
--  Lightweight anti-replay filter for WireGuard transport packets
--  (whitepaper section 5.4.5).
--
--  The filter tracks a 64-bit bitmap of recently seen counters.
--  After AEAD authentication succeeds, the counter is checked
--  against the window.  Duplicate, too-old, and over-limit
--  counters are rejected.
--
--  Design:
--    H  -- highest accepted counter value  (Unsigned_64)
--    B  -- 64-bit bitmap; bit k represents counter H - k
--    Window of 64 packets; ideal for low-traffic MCU targets
--
--  SPARK properties:
--    No runtime errors (overflow, range, index)
--    Pure arithmetic -- no pointers, no aliasing, no heap
--    Invariant: for every accepted counter c,
--      H - 63 <= c <= H  and  bit (H - c) of B is set.

with Interfaces; use Interfaces;

package Replay
  with SPARK_Mode => On
is

   Window_Size : constant := 64;

   type Filter is record
      Last   : Unsigned_64;  --  H: highest accepted counter
      Bitmap : Unsigned_64;  --  B: sliding window bitmap
   end record;

   Empty_Filter : constant Filter :=
     (Last => 0, Bitmap => 0);

   --  Reset -- Clear filter to initial state
   procedure Reset (F : out Filter)
   with Global => null,
        Post   => F.Last = 0 and then F.Bitmap = 0;

   --  Validate_Counter -- Check if counter should be accepted
   --
   --  Three cases for incoming counter C vs highest H:
   --    C > H          -> slide window forward, accept
   --    H-63 <= C <= H -> check/set bitmap bit
   --    C < H-63       -> too old, reject
   --
   --  Must be called ONLY after AEAD authentication succeeds.
   procedure Validate_Counter
     (F        : in out Filter;
      Counter  : Unsigned_64;
      Limit    : Unsigned_64;
      Accepted : out Boolean)
   with Global => null,
        Post   =>
          (if Accepted then
             Counter <= F.Last
             and then F.Last - Counter < Window_Size);

end Replay;
