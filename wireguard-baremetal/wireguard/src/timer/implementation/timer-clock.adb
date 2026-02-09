--  Timer.Clock - Implementation delegating to platform backend

with Timer.Platform;

package body Timer.Clock
  with SPARK_Mode => Off
is

   function Now return Timestamp is
   begin
      return Timer.Platform.Clock_Now;
   end Now;

end Timer.Clock;
