with Crypto.Platform;
with Interfaces.C;

package body Crypto.Helper
  with SPARK_Mode => Off
is
   procedure Memzero (Buffer : in out Byte_Array) is
      use Interfaces.C;
   begin
      Crypto.Platform.Crypto_Memzero
        (Buffer_In   => Buffer'Address,
         Buffer_Size => size_t (Buffer'Length));
   end Memzero;

   procedure Cmp
     (A      : Byte_Array;
      B      : Byte_Array;
      Result : out Status)
   is
      use Interfaces.C;
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Platform.Crypto_Cmp
        (A_In   => A'Address,
         B_in   => B'Address,
         Length => size_t (A'Length));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Cmp;

end Crypto.Helper;
