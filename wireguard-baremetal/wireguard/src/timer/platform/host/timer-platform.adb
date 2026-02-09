--  Timer.Platform - POSIX host implementation
--
--  Uses C clock_gettime(CLOCK_MONOTONIC) via import.
--  This is a simple binding — the C function returns seconds directly.

with Interfaces.C;

package body Timer.Platform
  with SPARK_Mode => Off
is

   --  C helper: returns CLOCK_MONOTONIC seconds as uint64_t
   function C_Clock_Now return Timer.Clock.Timestamp
     with Import, Convention => C,
          External_Name => "wg_clock_now";

   function Clock_Now return Timer.Clock.Timestamp is
   begin
      return C_Clock_Now;
   end Clock_Now;

end Timer.Platform;
