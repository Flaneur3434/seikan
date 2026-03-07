--  XChaCha20-Poly1305 AEAD implementation using libsodium

with Crypto.Crypto_Lib;
with Interfaces.C; use Interfaces.C;
with System;

package body Crypto.XAEAD
  with SPARK_Mode => Off
is

   procedure Encrypt
     (Plaintext  : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : Nonce_Buffer;
      Key        : Key_Buffer;
      Ciphertext : out Byte_Array;
      Result     : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Crypto_Lib.XAEAD_Encrypt
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
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Encrypt;

   procedure Decrypt
     (Ciphertext : Byte_Array;
      Ad         : Byte_Array;
      Nonce      : Nonce_Buffer;
      Key        : Key_Buffer;
      Plaintext  : out Byte_Array;
      Result     : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Crypto_Lib.XAEAD_Decrypt
          (Message_Out     => Plaintext'Address,
           Message_Len_Out => System.Null_Address,
           Nsec            => System.Null_Address,
           Ciphertext_In   => Ciphertext'Address,
           Ciphertext_Len  => unsigned_long_long (Ciphertext'Length),
           Ad_In           => Ad'Address,
           Ad_Len          => unsigned_long_long (Ad'Length),
           Nonce_In        => Nonce'Address,
           Key_In          => Key'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Decrypt;

end Crypto.XAEAD;
