--  Threads - Platform-independent threading primitives
--
--  Provides OS-level threading services (mutexes, etc.) with platform-specific
--  backends. Follows the same pattern as Crypto:
--
--    interfaces/       — Platform-independent specs
--    implementation/   — Bodies that call into Threads.Platform
--    platform/esp_idf/ — FreeRTOS bindings
--    platform/host/    — POSIX pthreads bindings
--
--  Currently provides:
--    Threads.Mutex — Mutual exclusion for shared data structures

package Threads
  with SPARK_Mode => On,
       Pure
is
   pragma Pure;
end Threads;
