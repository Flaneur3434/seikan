--  X25519 implementation using libsodium (cross-platform)

with Crypto.Sodium;
with Interfaces.C;

package body Crypto.X25519
  with SPARK_Mode => Off
is
   procedure Generate_Key_Pair
     (Key    : out Key_Pair;
      Result : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Sodium.Crypto_Box_Keypair
        (Public_Key_Out => Key.Public_Key'Address,
         Secret_Key_Out => Key.Secret_Key'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Generate_Key_Pair;

   procedure Scalar_Mult_Base
     (Public_Key : out X25519_Public_Key;
      Secret_Key : X25519_Secret_Key;
      Result     : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Sodium.Crypto_Scalarmult_Base
        (Public_Key_Out => Public_Key'Address,
         Secret_Key_In  => Secret_Key'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Scalar_Mult_Base;

   procedure Scalar_Mult
     (Shared_Secret : out X25519_Shared_Secret;
      My_Secret     : X25519_Secret_Key;
      Their_Public  : X25519_Public_Key;
      Result        : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Sodium.Crypto_Scalarmult
        (Shared_Secret_Out   => Shared_Secret'Address,
         My_Secret_Key_In    => My_Secret'Address,
         Their_Public_Key_In => Their_Public'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Scalar_Mult;

end Crypto.X25519;
