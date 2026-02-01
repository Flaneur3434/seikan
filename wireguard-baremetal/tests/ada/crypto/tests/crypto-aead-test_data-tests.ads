--  This package has been generated automatically by GNATtest.
--  Do not edit any part of it, see GNATtest documentation for more details.

--  begin read only
with Gnattest_Generated;

package Crypto.AEAD.Test_Data.Tests is

   type Test is new GNATtest_Generated.GNATtest_Standard.Crypto.AEAD.Test_Data.Test
   with null record;

   procedure Test_Encrypt_19b2d1 (Gnattest_T : in out Test);
   --  crypto-aead.ads:58:4:Encrypt

   procedure Test_Decrypt_3665e2 (Gnattest_T : in out Test);
   --  crypto-aead.ads:74:4:Decrypt

   procedure Test_Encrypt_In_Place_7311b6 (Gnattest_T : in out Test);
   --  crypto-aead.ads:110:4:Encrypt_In_Place

   procedure Test_Decrypt_In_Place_173bcf (Gnattest_T : in out Test);
   --  crypto-aead.ads:138:4:Decrypt_In_Place

   procedure Test_Build_Nonce_913f8b (Gnattest_T : in out Test);
   --  crypto-aead.ads:159:4:Build_Nonce

end Crypto.AEAD.Test_Data.Tests;
--  end read only
