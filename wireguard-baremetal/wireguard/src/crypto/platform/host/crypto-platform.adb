--  Platform-specific implementation: Host (Linux)

with System.Storage_Elements;

package body Crypto.Platform
  with SPARK_Mode => Off
is
   use System.Storage_Elements;

   procedure Random_Bytes (Buffer : System.Address; Size : size_t) is
      Remaining : size_t := Size;
      Offset    : Storage_Offset := 0;
      Result    : long;
   begin
      --  getrandom may return fewer bytes than requested, so loop
      while Remaining > 0 loop
         Result := Getrandom
           (Buffer + Offset,
            Remaining,
            0);  --  flags=0: block until entropy available

         if Result <= 0 then
            --  Error or interrupted - in production would handle better
            --  For now, just retry
            null;
         else
            Remaining := Remaining - size_t (Result);
            Offset := Offset + Storage_Offset (Result);
         end if;
      end loop;
   end Random_Bytes;

end Crypto.Platform;
