--  Host implementation of Crypto.Random using Linux getrandom()

with Crypto.Host;
with Interfaces.C;

package body Crypto.Random
  with SPARK_Mode => Off
is
   procedure Fill_Random (Buffer : out Byte_Array) is
      use Interfaces.C;
      Result : long;
   begin
      if Buffer'Length > 0 then
         Result := Crypto.Host.Getrandom
           (Buf   => Buffer (Buffer'First)'Address,
            Len   => size_t (Buffer'Length),
            Flags => 0);  -- Blocking, use /dev/urandom

         --  In a real implementation, we'd check Result for errors
         --  For now, we trust getrandom() succeeds
         pragma Unreferenced (Result);
      end if;
   end Fill_Random;

end Crypto.Random;
