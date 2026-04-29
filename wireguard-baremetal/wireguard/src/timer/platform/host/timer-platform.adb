--  Timer.Platform - POSIX host implementation
--
--  Uses Ada.Real_Time monotonic clock.
--  Returns milliseconds since Boot_Time.

with Interfaces.C;
with Ada.Real_Time; use Ada.Real_Time;

package body Timer.Platform
  with SPARK_Mode => Off
is

   function Clock_Now return Timer.Clock.Timestamp is
      Elapsed : constant Time_Span := Ada.Real_Time.Clock - Boot_Time;
   begin
      --  Convert to milliseconds
      return
        Timer.Clock.Timestamp
          (Interfaces.Unsigned_64 (To_Duration (Elapsed) * 1_000.0));
   end Clock_Now;

end Timer.Platform;
