--  Key Exchange implementation using crypto library backend

with Crypto.Crypto_Lib;
with Interfaces.C; use Interfaces.C;

package body Crypto.KX
  with SPARK_Mode => Off
is
   procedure Generate_Key_Pair (Key : out Key_Pair; Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Crypto_Lib.Generate_Keypair
          (Public_Key_Out => Key.Pub'Address,
           Secret_Key_Out => Key.Sec'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Generate_Key_Pair;

   procedure Derive_Public_Key
     (Pub : out Public_Key; Sec : Secret_Key; Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Crypto_Lib.Derive_Public_Key
          (Public_Key_Out => Pub'Address, Secret_Key_In => Sec'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Derive_Public_Key;

   procedure DH
     (Shared       : out Shared_Secret;
      My_Secret    : Secret_Key;
      Their_Public : Public_Key;
      Result       : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Crypto_Lib.DH_Key_Exchange
          (Shared_Secret_Out   => Shared'Address,
           My_Secret_Key_In    => My_Secret'Address,
           Their_Public_Key_In => Their_Public'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end DH;

end Crypto.KX;
