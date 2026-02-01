with Crypto.Crypto_Lib;
with Interfaces.C; use Interfaces.C;

package body Crypto.Helper
  with SPARK_Mode => Off
is
   procedure Memzero (Buffer : in out Byte_Array) is
   begin
      Crypto.Crypto_Lib.Secure_Wipe
        (Buffer => Buffer'Address,
         Size   => size_t (Buffer'Length));
   end Memzero;

   function Cmp
     (A : Byte_Array;
      B : Byte_Array) return Status
   is
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Crypto_Lib.Constant_Time_Compare
        (A      => A'Address,
         B      => B'Address,
         Length => size_t (A'Length));

      if Ret_Val = 0 then
         return Success;
      else
         return Error_Failed;
      end if;
   end Cmp;

end Crypto.Helper;
