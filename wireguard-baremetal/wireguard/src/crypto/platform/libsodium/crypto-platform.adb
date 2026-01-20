--  Platform initialization for libsodium
--
--  This body exists solely to call sodium_init() during elaboration.

package body Crypto.Platform
  with SPARK_Mode => Off
is
   Init_Result : Interfaces.C.int;
begin
   --  Initialize libsodium. Must be called before any other function.
   --  Returns: 0 = success, 1 = already initialized, -1 = failure
   Init_Result := Sodium_Init;

   --  In a real system we might want to handle Init_Result = -1,
   --  but sodium_init failure is catastrophic (no crypto available).
   pragma Assert (Init_Result >= 0, "sodium_init failed");
end Crypto.Platform;
