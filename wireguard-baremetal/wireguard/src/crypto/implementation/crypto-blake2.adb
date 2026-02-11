with Crypto.Blake2_Ref;
with System;

package body Crypto.Blake2
  with SPARK_Mode => Off
is
   ---------------------
   --  Unkeyed hash
   ---------------------

   --  Compute a BLAKE2s-256 digest over Data in a single call.
   --  No key is used — this is a pure cryptographic hash.
   --  Used by WireGuard's HASH() construction to build the
   --  chaining hash during the Noise IKpsk2 handshake.
   procedure Blake2s
     (Data   : Byte_Array;
      Digest : out Digest_Buffer;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s
          (Buffer_Out      => Digest'Address,
           Buffer_Out_Size => size_t (Digest'Length),
           Buffer_In       => Data'Address,
           Buffer_In_Size  => size_t (Data'Length),
           Key_In          => System.Null_Address,
           Key_In_Size     => 0);

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s;

   ---------------------
   --  Keyed hash
   ---------------------

   --  Compute a keyed BLAKE2s-256 MAC over Data.
   --  Used by WireGuard's MAC() construction to produce MAC1
   --  (authentication tag) in handshake initiation and response
   --  messages.  The key is the HASH("mac1----" ‖ responder_pub).
   procedure Blake2s
     (Data   : Byte_Array;
      Key    : Key_Buffer;
      Digest : out Digest_Buffer;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s
          (Buffer_Out      => Digest'Address,
           Buffer_Out_Size => size_t (Digest'Length),
           Buffer_In       => Data'Address,
           Buffer_In_Size  => size_t (Data'Length),
           Key_In          => Key'Address,
           Key_In_Size     => size_t (Key'Length));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s;

   --  Initialize a streaming BLAKE2s context for incremental hashing.
   --  Outlen specifies the desired digest length (1..32 bytes).
   --  After init, feed data with Blake2s_Update and finalize with
   --  Blake2s_Final.  Used when the message is built incrementally
   --  (e.g. chaining multiple fields into a single hash).
   procedure Blake2s_Init
     (Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Init
          (State => State'Unchecked_Access, Outlen => size_t (Outlen));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s_Init;

   --  Initialize a streaming BLAKE2s context with a key for
   --  incremental MAC computation.  Combines the streaming API
   --  with keyed mode — feed data with Blake2s_Update, finalize
   --  with Blake2s_Final to produce a keyed MAC digest.
   procedure Blake2s_Init_Key
     (Key    : Key_Buffer;
      Outlen : Digest_Length;
      State  : aliased out Blake2s_State;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Init_Key
          (State  => State'Unchecked_Access,
           Outlen => size_t (Outlen),
           Key_In => Key'Address,
           Keylen => size_t (Key'Length));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s_Init_Key;

   --  Feed additional data into a streaming BLAKE2s context.
   --  May be called zero or more times between Init and Final.
   --  Each call appends Data to the running hash computation.
   procedure Blake2s_Update
     (Data   : Byte_Array;
      State  : aliased in out Blake2s_State;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Update
          (State => State'Unchecked_Access,
           Data  => Data'Address,
           Len   => size_t (Data'Length));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s_Update;

   --  Finalize the streaming BLAKE2s context and write the digest.
   --  Digest'Length must match the Outlen given at Init time.
   --  After this call the State is consumed and must not be reused.
   procedure Blake2s_Final
     (State  : aliased in out Blake2s_State;
      Digest : out Byte_Array;
      Result : out Status)
   is
      Ret_Val : int;
   begin
      Ret_Val :=
        Crypto.Blake2_Ref.Blake2s_Final
          (State  => State'Unchecked_Access,
           Output => Digest'Address,
           Outlen => size_t (Digest'Length));

      if Ret_Val = 0 then
         Result := Success;
      else
         Result := Error_Failed;
      end if;
   end Blake2s_Final;

end Crypto.Blake2;
