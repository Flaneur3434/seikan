--  Timer.Platform - POSIX backend for monotonic clock (host builds)
--
--  This is a PRIVATE package — only visible within Timer hierarchy.
--  Uses clock_gettime(CLOCK_MONOTONIC) for host development/testing.

with Timer.Clock;

private package Timer.Platform
  with SPARK_Mode => Off
is

   --  Return monotonic seconds since boot.
   function Clock_Now return Timer.Clock.Timestamp;

end Timer.Platform;
