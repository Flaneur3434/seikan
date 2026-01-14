--  ESP-IDF platform bindings for ESP32
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  External users should use Crypto.Random.Fill_Random instead.

with System;
with Interfaces.C;

private package Crypto.ESP_IDF
  with SPARK_Mode => Off
is
   --  void esp_fill_random(void *buf, size_t len);
   procedure ESP_Fill_Random (Buf : System.Address; Len : Interfaces.C.size_t)
   with Import => True,
        Convention => C,
        External_Name => "esp_fill_random";

end Crypto.ESP_IDF;
