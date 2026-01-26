--  This package has been generated automatically by GNATtest.
--  Do not edit any part of it, see GNATtest documentation for more details.

--  begin read only
with Gnattest_Generated;

package Crypto.ChaCha20Poly1305.Test_Data.Tests is

   type Test is new GNATtest_Generated.GNATtest_Standard.Crypto.ChaCha20Poly1305.Test_Data.Test
   with null record;

   procedure Test_Encrypt_fb0bd2 (Gnattest_T : in out Test);
   --  crypto-chacha20poly1305.ads:50:4:Encrypt

   procedure Test_Decrypt_3205b1 (Gnattest_T : in out Test);
   --  crypto-chacha20poly1305.ads:65:4:Decrypt

   procedure Test_Encrypt_In_Place_4edb45 (Gnattest_T : in out Test);
   --  crypto-chacha20poly1305.ads:101:4:Encrypt_In_Place

   procedure Test_Decrypt_In_Place_84b536 (Gnattest_T : in out Test);
   --  crypto-chacha20poly1305.ads:128:4:Decrypt_In_Place

   procedure Test_Build_Nonce_913f8b (Gnattest_T : in out Test);
   --  crypto-chacha20poly1305.ads:145:4:Build_Nonce

end Crypto.ChaCha20Poly1305.Test_Data.Tests;
--  end read only
