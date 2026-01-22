with Crypto.Platform;
with Interfaces.C;
with System;

package body Crypto.ChaCha20Poly1305
  with SPARK_Mode => Off
is
   procedure Encrypt
     (Plaintext_Span  : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      Ciphertext_Span : Byte_Span; -- technically out parameter
      Result          : out Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_AEAD_ChaCha20Poly1305_IETF_Encrypt
          (Ciphertext_Out     => Data (Ciphertext_Span),
           Ciphertext_Len_Out => System.Null_Address,
           Message_In         => Data (Plaintext_Span),
           Message_Len        => unsigned_long_long (Length (Plaintext_Span)),
           Ad_In              => Data (Ad_Span),
           Ad_Len             => unsigned_long_long (Length (Ad_Span)),
           Nsec               => System.Null_Address,
           Nonce_In           => Nonce'Address,
           Key_In             => Key'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Encrypt;

   procedure Decrypt
     (Ciphertext_Span : Byte_Span;
      Ad_Span         : Byte_Span;
      Nonce           : Nonce_Buffer;
      Key             : Key_Buffer;
      Plaintext_Span  : Byte_Span; -- technically out parameter
      Result          : out Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Platform.Crypto_AEAD_ChaCha20Poly1305_IETF_Decrypt
          (Message_Out     => Data (Plaintext_Span),
           Message_Len_Out => System.Null_Address,
           Nsec            => System.Null_Address,
           Ciphertext_In   => Data (Ciphertext_Span),
           Ciphertext_Len  => unsigned_long_long (Length (Ciphertext_Span)),
           Ad_In           => Data (Ad_Span),
           Ad_Len          => unsigned_long_long (Length (Ad_Span)),
           Nonce_In        => Nonce'Address,
           Key_In          => Key'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Decrypt;

end Crypto.ChaCha20Poly1305;
