with Crypto.Platform;
with Interfaces.C;
with System;

package body Crypto.ChaCha20Poly1305
  with SPARK_Mode => Off
is
   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : ChaCha20Poly1305_Nonce;
      Key        : ChaCha20Poly1305_Key;
      Ciphertext : out Byte_Array;
      Result     : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_AEAD_ChaCha20Poly1305_IETF_Encrypt
          (Ciphertext_Out     => Ciphertext'Address,
           Ciphertext_Len_Out => System.Null_Address,
           Message_In         => Plaintext'Address,
           Message_Len        => unsigned_long_long (Plaintext'Length),
           Ad_In              => Ad'Address,
           Ad_Len             => unsigned_long_long (Ad'Length),
           Nsec               => System.Null_Address,
           Nonce_In           => Nonce'Address,
           Key_In             => Key'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Encrypt;

   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : ChaCha20Poly1305_Nonce;
      Key        : ChaCha20Poly1305_Key;
      Plaintext  : out Byte_Array;
      Result     : out Crypto.Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_AEAD_ChaCha20Poly1305_IETF_Decrypt
          (Message_Out     => Plaintext'Address,
           Message_Len_Out => System.Null_Address,
           Nsec            => System.Null_Address,
           Ciphertext_In   => Ciphertext'Address,
           Ciphertext_Len  => Ciphertext'Length,
           Ad_In           => Ad'Address,
           Ad_Len          => unsigned_long_long (Ad'Length),
           Nonce_In        => Nonce'Address,
           Key_In          => Key'Address);

      if Ret_Val = 0 then
         Result := Crypto.Success;
      else
         Result := Crypto.Error_Failed;
      end if;
   end Decrypt;

end Crypto.ChaCha20Poly1305;
