with Interfaces;
with Interfaces.C;

package Crypto.Blake2
  with SPARK_Mode => On
is
   use Interfaces;
   use Interfaces.C;

   --  BLAKE2s constants
   BLAKE2S_BLOCKBYTES : constant Positive := 64;   --  Block size
   BLAKE2S_OUTBYTES   : constant Positive := 32;   --  Digest size (256 bits)
   BLAKE2S_KEYBYTES   : constant Positive := 32;   --  Maximum key size

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

   ---------------------
   --  Simple API (all-in-one)
   ---------------------

   procedure Blake2s
     (Buffer_Out : out Byte_Array;
      Buffer_In  : Byte_Array;
      Key_Buffer : Byte_Array;
      Result     : out Crypto.Status)
   with Global => null, Pre => Buffer_Out'Length = BLAKE2S_OUTBYTES;

   ---------------------
   --  Streaming API (incremental hashing)
   ---------------------

   --  Initialize a new streaming hash context
   procedure Blake2s_Init
     (State  : aliased out Blake2s_State;
      Outlen : Positive;
      Result : out Crypto.Status)
   with Global => null, Pre => Outlen <= BLAKE2S_OUTBYTES;

   --  Initialize with a key
   procedure Blake2s_Init_Key
     (State  : aliased out Blake2s_State;
      Outlen : Positive;
      Key    : Byte_Array;
      Result : out Crypto.Status)
   with
     Global => null,
     Pre    =>
       Outlen <= BLAKE2S_OUTBYTES and then Key'Length <= BLAKE2S_KEYBYTES;

   --  Update hash with more data
   procedure Blake2s_Update
     (State  : aliased in out Blake2s_State;
      Data   : Byte_Array;
      Result : out Crypto.Status)
   with Global => null;

   --  Finalize and get the hash digest
   procedure Blake2s_Final
     (State  : aliased in out Blake2s_State;
      Digest : out Byte_Array;
      Result : out Crypto.Status)
   with Global => null;

end Crypto.Blake2;
