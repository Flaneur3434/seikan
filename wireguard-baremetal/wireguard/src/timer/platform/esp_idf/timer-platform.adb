with Interfaces;

package body Timer.Platform
  with SPARK_Mode => Off
is

   use Interfaces;

   function Get_Clock_Now return Interfaces.Unsigned_64
   with Import, Convention => C, External_Name => "esp_timer_get_time";

   function Clock_Now return Timer.Clock.Timestamp is
   begin
      --  Convert microseconds to milliseconds
      return Get_Clock_Now / 1_000;
   end Clock_Now;

end Timer.Platform;
