--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.AEAD.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.AEAD;
with Crypto.Random;
with Utils; use Utils;

--  begin read only
--  end read only
package body Crypto.AEAD.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_Encrypt (Gnattest_T : in out Test);
   procedure Test_Encrypt_19b2d1 (Gnattest_T : in out Test) renames Test_Encrypt;
--  id:2.2/19b2d16c138ca78b/Encrypt/1/0/
   procedure Test_Encrypt (Gnattest_T : in out Test) is
   --  crypto-aead.ads:58:4:Encrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      Plaintext  : Byte_Array (0 .. 63);
      Ad         : Byte_Array (0 .. 15);
      Ciphertext : Byte_Array (0 .. Plaintext'Length + Crypto.AEAD.Tag_Bytes - 1);
      Nonce_Buf  : Crypto.AEAD.Nonce_Buffer;
      Key_Buf    : Crypto.AEAD.Key_Buffer;
      Result     : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Plaintext);
      Crypto.Random.Fill_Random (Ad);

      --  Encrypt the test plaintext
      Crypto.AEAD.Encrypt
        (Plaintext  => Plaintext,
         Ad         => Ad,
         Nonce      => Nonce_Buf,
         Key        => Key_Buf,
         Ciphertext => Ciphertext,
         Result     => Result);

      --  Check encryption succeeded
      Assert (Result = Success, "Encrypt should succeed");

      --  Verify ciphertext is not all zeros (encryption did something)
      declare
         All_Zeros : Boolean := True;
      begin
         for I in Ciphertext'Range loop
            if Ciphertext (I) /= 0 then
               All_Zeros := False;
               exit;
            end if;
         end loop;
         Assert (not All_Zeros, "Ciphertext should not be all zeros");
      end;

--  begin read only
   end Test_Encrypt;
--  end read only


--  begin read only
   procedure Test_Decrypt (Gnattest_T : in out Test);
   procedure Test_Decrypt_3665e2 (Gnattest_T : in out Test) renames Test_Decrypt;
--  id:2.2/3665e2bd48ea9976/Decrypt/1/0/
   procedure Test_Decrypt (Gnattest_T : in out Test) is
   --  crypto-aead.ads:74:4:Decrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      Original_Pt     : Byte_Array (0 .. 63);
      Ad              : Byte_Array (0 .. 15);
      Ciphertext      : Byte_Array (0 .. Original_Pt'Length + Crypto.AEAD.Tag_Bytes - 1);
      Decrypted_Pt    : Byte_Array (Original_Pt'Range);
      Nonce_Buf       : Crypto.AEAD.Nonce_Buffer;
      Key_Buf         : Crypto.AEAD.Key_Buffer;
      Enc_Result      : Status;
      Dec_Result      : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Original_Pt);
      Crypto.Random.Fill_Random (Ad);

      --  First encrypt to get valid ciphertext
      Crypto.AEAD.Encrypt
        (Plaintext  => Original_Pt,
         Ad         => Ad,
         Nonce      => Nonce_Buf,
         Key        => Key_Buf,
         Ciphertext => Ciphertext,
         Result     => Enc_Result);
      Assert (Enc_Result = Success, "Encrypt for decrypt test should succeed");

      --  Test successful decryption
      Crypto.AEAD.Decrypt
        (Ciphertext => Ciphertext,
         Ad         => Ad,
         Nonce      => Nonce_Buf,
         Key        => Key_Buf,
         Plaintext  => Decrypted_Pt,
         Result     => Dec_Result);

      Assert (Dec_Result = Success, "Decrypt should succeed with valid tag");
      Assert (Decrypted_Pt = Original_Pt, "Decrypted text should match");

      --  Test decryption with tampered ciphertext (should fail)
      declare
         Tampered        : Byte_Array := Ciphertext;
         Tampered_Pt     : Byte_Array (Original_Pt'Range);
         Tampered_Result : Status;
      begin
         --  Flip a bit in the ciphertext
         Tampered (0) := Tampered (0) xor 16#01#;

         Crypto.AEAD.Decrypt
           (Ciphertext => Tampered,
            Ad         => Ad,
            Nonce      => Nonce_Buf,
            Key        => Key_Buf,
            Plaintext  => Tampered_Pt,
            Result     => Tampered_Result);

         Assert (Tampered_Result /= Success,
                 "Decrypt should fail with tampered ciphertext");
      end;

--  begin read only
   end Test_Decrypt;
--  end read only


--  begin read only
   procedure Test_Encrypt_In_Place (Gnattest_T : in out Test);
   procedure Test_Encrypt_In_Place_7311b6 (Gnattest_T : in out Test) renames Test_Encrypt_In_Place;
--  id:2.2/7311b6082edd17e7/Encrypt_In_Place/1/0/
   procedure Test_Encrypt_In_Place (Gnattest_T : in out Test) is
   --  crypto-aead.ads:110:4:Encrypt_In_Place
--  end read only

      pragma Unreferenced (Gnattest_T);

      Plaintext_Len : constant Natural := 64;
      --  Buffer: Header (16) + Plaintext (64) + Tag
      Buffer : Byte_Array (0 .. Crypto.AEAD.Header_Bytes + Plaintext_Len +
                                Crypto.AEAD.Tag_Bytes - 1);
      Original_Pt : Byte_Array (0 .. Plaintext_Len - 1);
      Nonce_Buf   : Crypto.AEAD.Nonce_Buffer;
      Key_Buf     : Crypto.AEAD.Key_Buffer;
      Result      : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Buffer);

      --  Save original plaintext for later comparison
      Original_Pt := Buffer (Crypto.AEAD.Header_Bytes ..
                             Crypto.AEAD.Header_Bytes + Plaintext_Len - 1);

      --  Encrypt in place
      Crypto.AEAD.Encrypt_In_Place
        (Buffer        => Buffer,
         Plaintext_Len => Plaintext_Len,
         Nonce         => Nonce_Buf,
         Key           => Key_Buf,
         Result        => Result);

      Assert (Result = Success, "Encrypt_In_Place should succeed");

      --  Verify plaintext region changed (encrypted)
      declare
         Changed : Boolean := False;
      begin
         for I in 0 .. Plaintext_Len - 1 loop
            if Buffer (Crypto.AEAD.Header_Bytes + I) /= Original_Pt (I) then
               Changed := True;
               exit;
            end if;
         end loop;
         Assert (Changed, "Buffer should be modified after encryption");
      end;

--  begin read only
   end Test_Encrypt_In_Place;
--  end read only


--  begin read only
   procedure Test_Decrypt_In_Place (Gnattest_T : in out Test);
   procedure Test_Decrypt_In_Place_173bcf (Gnattest_T : in out Test) renames Test_Decrypt_In_Place;
--  id:2.2/173bcfc18c21357c/Decrypt_In_Place/1/0/
   procedure Test_Decrypt_In_Place (Gnattest_T : in out Test) is
   --  crypto-aead.ads:138:4:Decrypt_In_Place
--  end read only

      pragma Unreferenced (Gnattest_T);

      Plaintext_Len  : constant Natural := 64;
      Ciphertext_Len : constant Natural := Plaintext_Len + Crypto.AEAD.Tag_Bytes;
      --  Buffer: Header (16) + Plaintext/Ciphertext (64) + Tag
      Buffer : Byte_Array (0 .. Crypto.AEAD.Header_Bytes + Ciphertext_Len - 1);
      Original_Pt : Byte_Array (0 .. Plaintext_Len - 1);
      Nonce_Buf   : Crypto.AEAD.Nonce_Buffer;
      Key_Buf     : Crypto.AEAD.Key_Buffer;
      Enc_Result  : Status;
      Dec_Result  : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Buffer);

      --  Save original plaintext
      Original_Pt := Buffer (Crypto.AEAD.Header_Bytes ..
                             Crypto.AEAD.Header_Bytes + Plaintext_Len - 1);

      --  Encrypt in place first
      Crypto.AEAD.Encrypt_In_Place
        (Buffer        => Buffer,
         Plaintext_Len => Plaintext_Len,
         Nonce         => Nonce_Buf,
         Key           => Key_Buf,
         Result        => Enc_Result);
      Assert (Enc_Result = Success, "Encrypt for decrypt test should succeed");

      --  Decrypt in place
      Crypto.AEAD.Decrypt_In_Place
        (Buffer         => Buffer,
         Ciphertext_Len => Ciphertext_Len,
         Nonce          => Nonce_Buf,
         Key            => Key_Buf,
         Result         => Dec_Result);

      Assert (Dec_Result = Success, "Decrypt_In_Place should succeed");

      --  Verify plaintext matches original
      declare
         Decrypted : constant Byte_Array :=
           Buffer (Crypto.AEAD.Header_Bytes ..
                   Crypto.AEAD.Header_Bytes + Plaintext_Len - 1);
      begin
         Assert (Decrypted = Original_Pt,
                 "Round-trip in-place should restore original plaintext");
      end;

--  begin read only
   end Test_Decrypt_In_Place;
--  end read only


--  begin read only
   procedure Test_Build_Nonce (Gnattest_T : in out Test);
   procedure Test_Build_Nonce_913f8b (Gnattest_T : in out Test) renames Test_Build_Nonce;
--  id:2.2/913f8b836797e1ae/Build_Nonce/1/0/
   procedure Test_Build_Nonce (Gnattest_T : in out Test) is
   --  crypto-aead.ads:159:4:Build_Nonce
--  end read only

      pragma Unreferenced (Gnattest_T);

      use Interfaces;

      Nonce1 : Crypto.AEAD.Nonce_Buffer;
      Nonce2 : Crypto.AEAD.Nonce_Buffer;

   begin
      --  Build nonces from different counters
      Crypto.AEAD.Build_Nonce (0, Nonce1);
      Crypto.AEAD.Build_Nonce (1, Nonce2);

      --  If nonce size > 0, nonces from different counters should differ
      if Crypto.AEAD.Nonce_Bytes > 0 then
         declare
            Different : Boolean := False;
         begin
            for I in Nonce1'Range loop
               if Nonce1 (I) /= Nonce2 (I) then
                  Different := True;
                  exit;
               end if;
            end loop;
            Assert (Different, "Nonces from different counters should differ");
         end;
      end if;

      --  Build same counter twice should give same nonce
      declare
         Nonce_A : Crypto.AEAD.Nonce_Buffer;
         Nonce_B : Crypto.AEAD.Nonce_Buffer;
      begin
         Crypto.AEAD.Build_Nonce (42, Nonce_A);
         Crypto.AEAD.Build_Nonce (42, Nonce_B);
         Assert (Nonce_A = Nonce_B,
                 "Same counter should produce same nonce");
      end;

--  begin read only
   end Test_Build_Nonce;
--  end read only

--  begin read only
--  id:2.2/02/
--
--  This section can be used to add elaboration code for the global state.
--
begin
--  end read only
   null;
--  begin read only
--  end read only
end Crypto.AEAD.Test_Data.Tests;
