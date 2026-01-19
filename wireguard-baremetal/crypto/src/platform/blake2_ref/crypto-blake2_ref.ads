--  Platform-specific crypto bindings: BLAKE2 reference implementation
--
--  This is a PRIVATE package - only visible within Crypto hierarchy.
--  Provides Ada bindings to the official BLAKE2 C reference code.

with System;
with Interfaces.C;
with Crypto.Blake2;

private package Crypto.Blake2_Ref
  with SPARK_Mode => Off
is
   use Interfaces.C;

   --  Import the public type
   subtype Blake2s_State is Crypto.Blake2.Blake2s_State;

   --  Typed pointer for type safety (must be general access to allow Unchecked_Access)
   type Blake2s_State_Ptr is access all Blake2s_State;

   ---------------------
   --  Simple API (all-in-one)
   ---------------------

   --  int blake2s( void *out, size_t outlen, const void *in, size_t inlen,
   --               const void *key, size_t keylen );
   --  Produces cryptographic hash in one call
   function Blake2s
     (Buffer_Out      : System.Address;
      Buffer_Out_Size : size_t;
      Buffer_In       : System.Address;
      Buffer_In_Size  : size_t;
      Key_In          : System.Address;
      Key_In_Size     : size_t) return int
   with Import, Convention => C, External_Name => "blake2s";

   ---------------------
   --  Streaming API
   ---------------------

   --  int blake2s_init( blake2s_state *S, size_t outlen );
   --  Initialize a BLAKE2s state for incremental hashing
   function Blake2s_Init
     (State : Blake2s_State_Ptr; Outlen : size_t) return int
   with Import, Convention => C, External_Name => "blake2s_init";

   --  int blake2s_init_key( blake2s_state *S, size_t outlen,
   --                        const void *key, size_t keylen );
   --  Initialize a BLAKE2s state with a key for incremental hashing
   function Blake2s_Init_Key
     (State  : Blake2s_State_Ptr;
      Outlen : size_t;
      Key_In : System.Address;
      Keylen : size_t) return int
   with Import, Convention => C, External_Name => "blake2s_init_key";

   --  int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
   --  Update the hash with more data
   function Blake2s_Update
     (State : Blake2s_State_Ptr; Data : System.Address; Len : size_t)
      return int
   with Import, Convention => C, External_Name => "blake2s_update";

   --  int blake2s_final( blake2s_state *S, void *out, size_t outlen );
   --  Finalize the hash and produce the digest
   function Blake2s_Final
     (State : Blake2s_State_Ptr; Output : System.Address; Outlen : size_t)
      return int
   with Import, Convention => C, External_Name => "blake2s_final";

end Crypto.Blake2_Ref;
