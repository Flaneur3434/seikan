--  Timer - Platform-independent timing primitives
--
--  Provides OS-level monotonic clock services with platform-specific
--  backends.  Follows the same pattern as Threads:
--
--    interfaces/       — Platform-independent specs
--    implementation/   — Bodies that call into Timer.Platform
--    platform/esp_idf/ — esp_timer bindings
--    platform/host/    — POSIX clock_gettime bindings
--
--  Currently provides:
--    Timer.Clock — Monotonic seconds-since-boot

package Timer
  with SPARK_Mode => On,
       Pure
is
   pragma Pure;
end Timer;
