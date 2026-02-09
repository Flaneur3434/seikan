--  Timer.Platform - ESP-IDF backend for monotonic clock
--
--  This is a PRIVATE package — only visible within Timer hierarchy.
--  Wraps esp_timer_get_time() via a thin C helper that divides by
--  1_000_000 to return seconds.
--
--  The C wrapper (wg_clock.c) is compiled by ESP-IDF's CMake build
--  system, not by gprbuild, because it needs ESP-IDF headers.

with Timer.Clock;

private package Timer.Platform
  with SPARK_Mode => Off
is

   --  Return monotonic seconds since boot.
   function Clock_Now return Timer.Clock.Timestamp
     with Import, Convention => C,
          External_Name => "wg_clock_now";

end Timer.Platform;
