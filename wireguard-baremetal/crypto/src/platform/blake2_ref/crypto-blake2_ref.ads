--  Platform-specific crypto bindings: BLAKE2 reference implementation
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides Ada bindings to the official BLAKE2 C reference code.

with System;
with Interfaces.C;

private package Crypto.Blake2_Ref
  with SPARK_Mode => Off
is
   use Interfaces.C;

   ---------------------
   --  Random Number Generation
   ---------------------

   --  int blake2s( void *out, size_t outlen, const void *in, size_t inlen,
   --               const void *key, size_t keylen );
   --  Produces cryptographic hash
   function Blake2s
     (Buffer_Out      : System.Address;
      Buffer_Out_Size : size_t;
      Buffer_In       : System.Address;
      Buffer_In_Size  : size_t;
      Key_In          : System.Address;
      Key_In_Size     : size_t)
      return int
   with Import, Convention => C, External_Name => "blake2s";

end Crypto.Blake2_Ref;
