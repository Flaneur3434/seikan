with Crypto.Platform;
with Interfaces.C; use Interfaces.C;
with Utils;

package body Crypto.Helper
  with SPARK_Mode => Off
is
   procedure Memzero (Buffer : in out Byte_Array) is
   begin
      Crypto.Platform.Crypto_Memzero
        (Buffer_In   => Buffer'Address,
         Buffer_Size => size_t (Buffer'Length));
   end Memzero;

   function Cmp
     (A : Byte_Array;
      B : Byte_Array) return Status
   is
      Ret_Val : int;
   begin
      Ret_Val := Crypto.Platform.Crypto_Cmp
        (A_In   => A'Address,
         B_in   => B'Address,
         Length => size_t (A'Length));

      if Ret_Val = 0 then
         return Success;
      else
         return Error_Failed;
      end if;
   end Cmp;

end Crypto.Helper;
