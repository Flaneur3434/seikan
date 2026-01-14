--  ESP-IDF platform bindings
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Contains ESP-IDF specific functions (not in libsodium).

with System;
with Interfaces.C;

private package Crypto.ESP_IDF
  with SPARK_Mode => Off
is
   --  void esp_fill_random(void *buf, size_t len);
   --  Hardware RNG - ESP32 specific
   procedure ESP_Fill_Random (Buf : System.Address; Len : Interfaces.C.size_t)
   with Import, Convention => C, External_Name => "esp_fill_random";

end Crypto.ESP_IDF;
