--  Timer.Clock - Monotonic clock interface
--
--  Provides a monotonic seconds-since-boot timestamp for WireGuard
--  timer deadlines (rekey, keepalive, reject).
--
--  Resolution is 1 second — sufficient for all WireGuard timers
--  (fastest event is keepalive at 10 seconds).
--
--  The underlying source is selected at build time:
--    esp_idf → esp_timer_get_time() / 1_000_000
--    host    → clock_gettime(CLOCK_MONOTONIC)

with Interfaces;

package Timer.Clock
  with SPARK_Mode => On
is
   use Interfaces;

   ---------------------------------------------------------------------------
   --  Timestamp
   --
   --  Seconds since system boot.  64-bit gives ~584 billion years.
   --  Value 0 means "never" / "not set" by convention.
   ---------------------------------------------------------------------------

   subtype Timestamp is Unsigned_64;

   Never : constant Timestamp := 0;

   ---------------------------------------------------------------------------
   --  Now — Current monotonic time in seconds
   ---------------------------------------------------------------------------

   function Now return Timestamp
     with Volatile_Function;
   --  Volatile_Function: result changes on each call (clock ticks).
   --  Not SPARK-provable (side-effectful), but that's expected for I/O.

end Timer.Clock;
