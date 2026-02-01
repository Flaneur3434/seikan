--  Platform-specific bindings: ESP-IDF (ESP32)
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides OS-level services like random number generation for ESP32.
--
--  For ESP-IDF builds, we use esp_random() which provides hardware RNG.

with System;
with Interfaces.C;

private package Crypto.Platform
  with SPARK_Mode => Off
is
   use Interfaces.C;

   ---------------------
   --  Random Number Generation
   ---------------------

   --  Fills buffer with cryptographically secure random bytes.
   --  Uses ESP32's hardware random number generator via esp_fill_random.
   procedure Random_Bytes (Buffer : System.Address; Size : size_t)
   with Import, Convention => C, External_Name => "esp_fill_random";

end Crypto.Platform;
