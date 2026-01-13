--  ESP-IDF implementation of Crypto.Random using hardware RNG

with Crypto.ESP_IDF;
with Interfaces.C;

package body Crypto.Random
  with SPARK_Mode => Off
is
   procedure Fill_Random (Buffer : out Byte_Array) is
      use Interfaces.C;
   begin
      if Buffer'Length > 0 then
         Crypto.ESP_IDF.ESP_Fill_Random
           (Buf => Buffer (Buffer'First)'Address,
            Len => size_t (Buffer'Length));
      end if;
   end Fill_Random;

end Crypto.Random;
