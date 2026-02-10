--  Timer.Platform - POSIX backend for monotonic clock (host builds)
--
--  This is a PRIVATE package — only visible within Timer hierarchy.
--  Uses clock_gettime(CLOCK_MONOTONIC) for host development/testing.

with Timer.Clock;
with Ada.Real_Time;

private package Timer.Platform
  with SPARK_Mode => Off
is

   --  Return monotonic seconds since boot.
   function Clock_Now return Timer.Clock.Timestamp;

private
   Boot_Time : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;

end Timer.Platform;
