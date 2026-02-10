--  Timer.Platform - POSIX host implementation
--
--  Uses C clock_gettime(CLOCK_MONOTONIC) via import.
--  This is a simple binding — the C function returns seconds directly.

with Interfaces.C;
with Ada.Real_Time; use Ada.Real_Time;

package body Timer.Platform
  with SPARK_Mode => Off
is

   function Clock_Now return Timer.Clock.Timestamp is
      Elapsed : constant Time_Span := Ada.Real_Time.Clock - Boot_Time;
   begin
      --  Convert to seconds
      return
        Timer.Clock.Timestamp (Interfaces.Unsigned_64 (To_Duration (Elapsed)));
   end Clock_Now;

end Timer.Platform;
