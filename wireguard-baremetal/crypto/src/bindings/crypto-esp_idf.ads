with System;
with Interfaces.C;

package Crypto.ESP_IDF
  with SPARK_Mode => Off
is
   --  void esp_fill_random(void *buf, size_t len);
   procedure ESP_Fill_Random (Buf : System.Address; Len : Interfaces.C.size_t)
   with Import => True,
        Convention => C,
        External_Name => "esp_fill_random";

end Crypto.ESP_IDF;
