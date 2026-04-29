--  Timer.Clock - Monotonic clock interface
--
--  Provides a monotonic milliseconds-since-boot timestamp for
--  WireGuard timer deadlines (rekey, keepalive, reject).
--
--  Resolution is 1 millisecond.  Milliseconds match the natural
--  granularity of WireGuard timers (5 s rekey retry, 10 s keepalive,
--  120 s rekey, 180 s reject, 540 s zero-keys) and eliminate the
--  seconds-level truncation that the previous one-second resolution
--  introduced at the Ada/C boundary.
--
--  The underlying source is selected at build time:
--    esp_idf → esp_timer_get_time() / 1_000
--    host    → clock_gettime(CLOCK_MONOTONIC), milliseconds

with Interfaces;

package Timer.Clock
  with SPARK_Mode => On
is
   use Interfaces;

   ---------------------------------------------------------------------------
   --  Timestamp
   --
   --  Milliseconds since system boot.  64-bit gives ~584 million years.
   --  Value 0 means "never" / "not set" by convention.
   ---------------------------------------------------------------------------

   subtype Timestamp is Unsigned_64;

   Never : constant Timestamp := 0;

   ---------------------------------------------------------------------------
   --  Now — Current monotonic time in milliseconds
   ---------------------------------------------------------------------------

   function Now return Timestamp
     with Volatile_Function;
   --  Volatile_Function: result changes on each call (clock ticks).
   --  Not SPARK-provable (side-effectful), but that's expected for I/O.

end Timer.Clock;
