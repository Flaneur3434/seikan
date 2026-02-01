--  Crypto library initialization: libsodium
--
--  Calls sodium_init() during elaboration.

package body Crypto.Crypto_Lib
  with SPARK_Mode => Off
is
   Init_Result : Interfaces.C.int;
begin
   Init_Result := Init;
   pragma Assert (Init_Result >= 0, "sodium_init failed");
end Crypto.Crypto_Lib;
