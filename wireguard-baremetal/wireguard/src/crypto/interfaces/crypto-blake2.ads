with Interfaces;
with Interfaces.C;

package Crypto.Blake2
  with SPARK_Mode => On
is
   use Interfaces;
   use Interfaces.C;

   --  BLAKE2s constants
   BLAKE2S_OUTBYTES : constant Positive := 32;   --  Digest size (256 bits)
   BLAKE2S_KEYBYTES : constant Positive := 32;   --  Maximum key size

   --  Public subtypes for buffers
   subtype Digest_Buffer is Byte_Array (0 .. BLAKE2S_OUTBYTES - 1);
   subtype Key_Buffer is Byte_Array (0 .. BLAKE2S_KEYBYTES - 1);
   subtype Digest_Length is Positive range 1 .. BLAKE2S_OUTBYTES;

   type Blake2s_State is private;

   ---------------------
   --  Simple API (all-in-one)
   ---------------------

   --  Unkeyed hash
   procedure Blake2s
     (Data   : Byte_Array;
      Digest : out Digest_Buffer;
      Result : out Crypto.Status)
   with Global => null;

   --  Keyed hash (MAC)
   procedure Blake2s
     (Data   : Byte_Array;
      Key    : Key_Buffer;
      Digest : out Digest_Buffer;
      Result : out Crypto.Status)
   with Global => null;

   ---------------------
   --  Streaming API (incremental hashing)
   ---------------------

   --  Initialize a new streaming hash context
   procedure Blake2s_Init
     (Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Crypto.Status)
   with Global => null;

   --  Initialize with a key
   procedure Blake2s_Init_Key
     (Key    : Key_Buffer;
      Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Crypto.Status)
   with Global => null;

   --  Update hash with more data
   procedure Blake2s_Update
     (Data   : Byte_Array;
      State  : aliased in out Blake2s_State;
      Result : out Crypto.Status)
   with Global => null;

   --  Finalize and get the hash digest
   procedure Blake2s_Final
     (State  : aliased in out Blake2s_State;
      Digest : out Byte_Array;
      Result : out Crypto.Status)
   with Global => null;

private
   --  BLAKE2s constants (internal)
   BLAKE2S_BLOCKBYTES : constant Positive := 64;   --  Block size

   --  Array types for BLAKE2s state components
   type Hash_Array is array (Natural range 0 .. 7) of Unsigned_32;
   type Counter_Array is array (Natural range 0 .. 1) of Unsigned_32;
   type Flags_Array is array (Natural range 0 .. 1) of Unsigned_32;
   type Buffer_Array is
     array (Natural range 0 .. BLAKE2S_BLOCKBYTES - 1) of Unsigned_8;

   --  BLAKE2s streaming state - same layout as C blake2s_state struct
   type Blake2s_State is record
      H         : Hash_Array;           --  Hash state
      T         : Counter_Array;        --  Counter
      F         : Flags_Array;          --  Finalization flags
      Buf       : Buffer_Array;         --  Input buffer
      Buflen    : Interfaces.C.size_t;  --  Buffer fill length
      Outlen    : Interfaces.C.size_t;  --  Output length
      Last_Node : Unsigned_8;           --  Is this the last node?
   end record
   with Convention => C;

end Crypto.Blake2;
