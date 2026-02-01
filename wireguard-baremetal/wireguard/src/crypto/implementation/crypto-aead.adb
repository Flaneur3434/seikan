--  AEAD implementation using crypto library backend

with Crypto.Crypto_Lib;
with Interfaces.C; use Interfaces.C;
with System;
with System.Storage_Elements;

package body Crypto.AEAD
  with SPARK_Mode => Off
is
   use System.Storage_Elements;

   ---------------------
   --  Standard Encrypt (separate buffers)
   ---------------------

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
        Crypto.Crypto_Lib.AEAD_Encrypt
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

   ---------------------
   --  Standard Decrypt (separate buffers)
   ---------------------

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
        Crypto.Crypto_Lib.AEAD_Decrypt
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

   ---------------------
   --  In-Place Encrypt (for TX path)
   ---------------------

   procedure Encrypt_In_Place
     (Buffer        : in out Byte_Array;
      Plaintext_Len : Natural;
      Nonce         : Nonce_Buffer;
      Key           : Key_Buffer;
      Result        : out Status)
   is
      Ret_Val : int;

      --  Header is AAD (bytes 0..Header_Bytes-1)
      Header_Addr : constant System.Address := Buffer'Address;

      --  Plaintext starts at offset Header_Bytes
      Plaintext_Addr : constant System.Address :=
        Buffer'Address + Storage_Offset (Header_Bytes);

      --  Ciphertext overwrites plaintext in same location
      --  Tag will be written at Plaintext_Addr + Plaintext_Len
      Ciphertext_Addr : constant System.Address := Plaintext_Addr;

   begin
      --  Encrypt function writes ciphertext + tag to output
      --  We use the same address for input plaintext and output ciphertext
      --  This works because stream ciphers are XOR-based
      Ret_Val :=
        Crypto.Crypto_Lib.AEAD_Encrypt
          (Ciphertext_Out     => Ciphertext_Addr,
           Ciphertext_Len_Out => System.Null_Address,
           Message_In         => Plaintext_Addr,
           Message_Len        => unsigned_long_long (Plaintext_Len),
           Ad_In              => Header_Addr,
           Ad_Len             => unsigned_long_long (Header_Bytes),
           Nsec               => System.Null_Address,
           Nonce_In           => Nonce'Address,
           Key_In             => Key'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Encrypt_In_Place;

   ---------------------
   --  In-Place Decrypt (for RX path)
   ---------------------

   procedure Decrypt_In_Place
     (Buffer         : in out Byte_Array;
      Ciphertext_Len : Natural;
      Nonce          : Nonce_Buffer;
      Key            : Key_Buffer;
      Result         : out Status)
   is
      Ret_Val : int;

      --  Header is AAD (bytes 0..Header_Bytes-1)
      Header_Addr : constant System.Address := Buffer'Address;

      --  Ciphertext + tag starts at offset Header_Bytes
      Ciphertext_Addr : constant System.Address :=
        Buffer'Address + Storage_Offset (Header_Bytes);

      --  Plaintext overwrites ciphertext in same location
      Plaintext_Addr : constant System.Address := Ciphertext_Addr;

   begin
      --  Decrypt function reads ciphertext + tag from input
      --  and writes plaintext to output. We use the same address.
      Ret_Val :=
        Crypto.Crypto_Lib.AEAD_Decrypt
          (Message_Out     => Plaintext_Addr,
           Message_Len_Out => System.Null_Address,
           Nsec            => System.Null_Address,
           Ciphertext_In   => Ciphertext_Addr,
           Ciphertext_Len  => unsigned_long_long (Ciphertext_Len),
           Ad_In           => Header_Addr,
           Ad_Len          => unsigned_long_long (Header_Bytes),
           Nonce_In        => Nonce'Address,
           Key_In          => Key'Address);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Decrypt_In_Place;

   ---------------------
   --  Build Nonce
   ---------------------

   procedure Build_Nonce (Counter : Unsigned_64; N : out Nonce_Buffer) is
      C : Unsigned_64 := Counter;

      --  Suppress warnings about constant conditions - these checks are
      --  intentionally compile-time constants that differ per backend:
      --    libsodium:   Nonce_Bytes = 12 (ChaCha20-Poly1305 IETF)
      --    libhydrogen: Nonce_Bytes = 0  (internal counter)
      pragma Warnings (Off, "condition is always*");
      pragma Warnings (Off, "unreachable code");
   begin
      --  Handle backends with no external nonce
      if Nonce_Bytes = 0 then
         --  Empty nonce, counter handled internally by backend
         N := (others => 0);
         return;
      end if;

      --  Standard format for 12-byte nonce: 0x00000000 || LE64(counter)
      if Nonce_Bytes = 12 then
         --  First 4 bytes are zero
         N (0) := 0;
         N (1) := 0;
         N (2) := 0;
         N (3) := 0;

         --  Last 8 bytes are counter in little-endian
         for I in 0 .. 7 loop
            N (4 + I) := Unsigned_8 (C and 16#FF#);
            C := Shift_Right (C, 8);
         end loop;
      else
         --  Generic: fill with little-endian counter, pad with zeros
         for I in N'Range loop
            if I < 8 then
               N (I) := Unsigned_8 (C and 16#FF#);
               C := Shift_Right (C, 8);
            else
               N (I) := 0;
            end if;
         end loop;
      end if;
   end Build_Nonce;

end Crypto.AEAD;
