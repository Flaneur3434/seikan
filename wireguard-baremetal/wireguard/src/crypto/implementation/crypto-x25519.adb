--  X25519 implementation using platform crypto backend

with Crypto.Platform;
with Interfaces.C;

package body Crypto.X25519
  with SPARK_Mode => Off
is
   procedure Generate_Key_Pair (Key : out Key_Pair; Result : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_Box_Keypair
          (Public_Key_Out => Key.Pub'Address,
           Secret_Key_Out => Key.Sec'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Generate_Key_Pair;

   procedure Scalar_Mult_Base
     (Pub : out Public_Key; Sec : Secret_Key; Result : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_Scalarmult_Base
          (Public_Key_Out => Pub'Address, Secret_Key_In => Sec'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Scalar_Mult_Base;

   procedure Scalar_Mult
     (Shared       : out Shared_Secret;
      My_Secret    : Secret_Key;
      Their_Public : Public_Key;
      Result       : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_Scalarmult
          (Shared_Secret_Out   => Shared'Address,
           My_Secret_Key_In    => My_Secret'Address,
           Their_Public_Key_In => Their_Public'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Scalar_Mult;

end Crypto.X25519;
