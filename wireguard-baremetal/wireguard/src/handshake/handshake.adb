--  Handshake - VeriGuard Noise IK Handshake Protocol Implementation
--
--  Implements Noise IK handshake pattern for WireGuard-style key agreement.

with Ada.Unchecked_Conversion;
with Crypto.Random;
with Crypto.AEAD;
with Transport_Messages;
pragma Unreferenced (Crypto.Random);
pragma Unreferenced (Transport_Messages);

package body Handshake
  with SPARK_Mode => On
is
   ---------------------
   --  Protocol Constants
   ---------------------

   --  Noise protocol construction string
   --  "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
   Construction : constant Byte_Array (0 .. Construction_Length - 1) :=
     (16#4E#, 16#6F#, 16#69#, 16#73#, 16#65#, 16#5F#,  --  "Noise_"
      16#49#, 16#4B#, 16#70#, 16#73#, 16#6B#, 16#32#,  --  "IKpsk2"
      16#5F#, 16#32#, 16#35#, 16#35#, 16#31#, 16#39#,  --  "_25519"
      16#5F#, 16#43#, 16#68#, 16#61#, 16#43#, 16#68#,  --  "_ChaCh"
      16#61#, 16#50#, 16#6F#, 16#6C#, 16#79#, 16#5F#,  --  "aPoly_"
      16#42#, 16#4C#, 16#41#, 16#4B#, 16#45#, 16#32#,  --  "BLAKE2"
      16#73#);                                          --  "s"

   --  WireGuard identifier string
   --  "WireGuard v1 zx2c4 Jason@zx2c4.com"
   Identifier : constant Byte_Array (0 .. Identifier_Length - 1) :=
     (16#57#, 16#69#, 16#72#, 16#65#, 16#47#, 16#75#,  --  "WireGu"
      16#61#, 16#72#, 16#64#, 16#20#, 16#76#, 16#31#,  --  "ard v1"
      16#20#, 16#7A#, 16#78#, 16#32#, 16#63#, 16#34#,  --  " zx2c4"
      16#20#, 16#4A#, 16#61#, 16#73#, 16#6F#, 16#6E#,  --  " Jason"
      16#40#, 16#7A#, 16#78#, 16#32#, 16#63#, 16#34#,  --  "@zx2c4"
      16#2E#, 16#63#, 16#6F#, 16#6D#);                 --  ".com"

   --  Label for MAC1 key derivation: "mac1----"
   Label_Mac1 : constant Byte_Array (0 .. Label_Mac1_Length - 1) :=
     (16#6D#, 16#61#, 16#63#, 16#31#,  --  "mac1"
      16#2D#, 16#2D#, 16#2D#, 16#2D#); --  "----"

   --  Reserved bytes (3 zeros)
   Reserved_Zero : constant Transport.Reserved_Bytes := (others => 0);

   ---------------------
   --  Local Session Index Counter (monotonic)
   ---------------------

   --  Simple monotonic counter for generating unique local session indices.
   --  In a full implementation, this would need to avoid reuse and possibly
   --  persist across reboots.
   --
   --  Wrap at 2^32 is acceptable: at 1 handshake/sec, wrap takes 136 years.
   --  Embedded devices will reboot long before that.
   Next_Local_Index : Session_Index := 1;

   function Allocate_Local_Index return Session_Index
     with SPARK_Mode => Off
   is
      Result : constant Session_Index := Next_Local_Index;
   begin
      Next_Local_Index := Next_Local_Index + 1;
      return Result;
   end Allocate_Local_Index;

   ---------------------
   --  Noise Protocol Helpers
   ---------------------

   --  MixHash: H = HASH(H || data)
   --  Updates the hash state by hashing the current hash with new data
   procedure Mix_Hash
     (H      : in out Hash_State;
      Data   : Byte_Array;
      Result : out Status)
   with SPARK_Mode => On
   is
      State       : aliased Crypto.Blake2.Blake2s_State;
      Local_Result : Status;
   begin
      --  Initialize BLAKE2s with output length 32
      Crypto.Blake2.Blake2s_Init
        (Outlen => Crypto.Blake2.BLAKE2S_OUTBYTES,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         return;
      end if;

      --  Update with current hash state
      Crypto.Blake2.Blake2s_Update
        (Data   => H,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         return;
      end if;

      --  Update with new data
      Crypto.Blake2.Blake2s_Update
        (Data   => Data,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         return;
      end if;

      --  Finalize into H
      Crypto.Blake2.Blake2s_Final
        (State  => State,
         Digest => H,
         Result => Result);
   end Mix_Hash;

   --  MixKey: (C, K) = KDF(C, input)
   --  Updates chaining key and derives a new encryption key.
   --
   --  WireGuard uses HKDF with BLAKE2s. We need two outputs from one input:
   --    1. New chaining key C' (for future derivations)
   --    2. Encryption key K (for immediate use)
   --
   --  HKDF-Expand derives each output by hashing with a counter byte:
   --    C' = HASH(C || input)        -- first derivation
   --    K  = HASH(C' || 0x01)        -- second derivation with counter
   --
   --  This is simpler than full HKDF (no extract step) because the Noise
   --  protocol already ensures input key material has sufficient entropy.
   procedure Mix_Key
     (C      : in out Chaining_Key;
      Input  : Byte_Array;
      K      : out Crypto.AEAD.Key_Buffer;
      Result : out Status)
   with SPARK_Mode => On
   is
      Temp         : Chaining_Key;
      State        : aliased Crypto.Blake2.Blake2s_State;
      One_Byte     : constant Byte_Array (0 .. 0) := (0 => 16#01#);
      Local_Result : Status;
   begin
      --  First: C' = HASH(C || input)
      Crypto.Blake2.Blake2s_Init
        (Outlen => Crypto.Blake2.BLAKE2S_OUTBYTES,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => C,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => Input,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Final
        (State  => State,
         Digest => Temp,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      --  Update C to C'
      C := Temp;

      --  Second: K = HASH(C' || 0x01)
      Crypto.Blake2.Blake2s_Init
        (Outlen => Crypto.Blake2.BLAKE2S_OUTBYTES,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => Temp,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => One_Byte,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         K := (others => 0);
         return;
      end if;

      Crypto.Blake2.Blake2s_Final
        (State  => State,
         Digest => K,
         Result => Result);
   end Mix_Key;

   --  Compute MAC1 = HASH(key || message)
   --  Truncated to 16 bytes for WireGuard MAC1/MAC2
   procedure Compute_Mac
     (Key     : Crypto.Blake2.Key_Buffer;
      Message : Byte_Array;
      Mac     : out Transport.Mac_Bytes;
      Result  : out Status)
   with SPARK_Mode => On
   is
      Full_Hash : Crypto.Blake2.Digest_Buffer;
   begin
      --  Compute keyed hash
      Crypto.Blake2.Blake2s
        (Data   => Message,
         Key    => Key,
         Digest => Full_Hash,
         Result => Result);

      if Is_Success (Result) then
         --  Truncate to MAC size (16 bytes)
         Mac := Full_Hash (0 .. Transport.Mac_Size - 1);
      else
         Mac := (others => 0);
      end if;
   end Compute_Mac;

   ---------------------
   --  Public Procedures
   ---------------------

   procedure Initialize_Identity
     (Identity : out Static_Identity;
      Key_Pair : Crypto.KX.Key_Pair;
      Result   : out Status)
   is
      Label_And_Public : Byte_Array
        (0 .. Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1);
   begin
      Identity.Key_Pair := Key_Pair;

      --  Compute MAC1 key: HASH(LABEL_MAC1 || static_public)
      Label_And_Public (0 .. Label_Mac1_Length - 1) := Label_Mac1;
      Label_And_Public (Label_Mac1_Length ..
                        Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1) :=
        Byte_Array (Key_Pair.Pub);

      Crypto.Blake2.Blake2s
        (Data   => Label_And_Public,
         Digest => Identity.Mac1_Key,
         Result => Result);
   end Initialize_Identity;

   procedure Initialize_Peer
     (Peer        : out Peer_Config;
      Peer_Public : Crypto.KX.Public_Key;
      Result      : out Status)
   is
      Label_And_Public : Byte_Array
        (0 .. Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1);
   begin
      Peer.Static_Public := Peer_Public;

      --  Compute MAC1 key: HASH(LABEL_MAC1 || peer_public)
      Label_And_Public (0 .. Label_Mac1_Length - 1) := Label_Mac1;
      Label_And_Public (Label_Mac1_Length ..
                        Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1) :=
        Byte_Array (Peer_Public);

      Crypto.Blake2.Blake2s
        (Data   => Label_And_Public,
         Digest => Peer.Mac1_Key,
         Result => Result);
   end Initialize_Peer;

   procedure Create_Initiation
     (Buffer   : in out Byte_Array;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Peer     : Peer_Config;
      Result   : out Initiation_Result)
   is
      Local_Status     : Status;
      Temp_Key         : Crypto.AEAD.Key_Buffer;
      Shared           : Crypto.KX.Shared_Secret;
      Timestamp        : aliased Crypto.TAI64N.Timestamp;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      --  Safety: each encryption uses a fresh key derived via Mix_Key,
      --  so (key, nonce) pairs are never reused.
      Nonce            : constant Crypto.AEAD.Nonce_Buffer := (others => 0);

      --  Message field offsets (computed from message structure)
      Msg_Type_Offset            : constant Natural := 0;
      Reserved_Offset            : constant Natural := 1;
      Sender_Offset              : constant Natural := 4;
      Ephemeral_Offset           : constant Natural := 8;
      Encrypted_Static_Offset    : constant Natural :=
        Ephemeral_Offset + Transport.Key_Size;
      Encrypted_Timestamp_Offset : constant Natural :=
        Encrypted_Static_Offset + Transport.Encrypted_Static_Size;
      Mac1_Offset                : constant Natural :=
        Encrypted_Timestamp_Offset + Transport.Encrypted_Timestamp_Size;
      Mac2_Offset                : constant Natural :=
        Mac1_Offset + Transport.Mac_Size;

      --  Local Index
      Local_Index : Session_Index;
   begin
      --  Initialize result
      Result := (Success => False, Length => 0);

      --  Generate ephemeral keypair
      Crypto.KX.Generate_Key_Pair (State.Ephemeral, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Allocate local session index
      Local_Index := Allocate_Local_Index;
      State.Local_Index := Local_Index;

      --  Initialize Noise protocol state
      --  C = HASH(Construction)
      Crypto.Blake2.Blake2s
        (Data   => Construction,
         Digest => State.Chaining,
         Result => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(C || Identifier)
      Mix_Hash (State.Chaining, Identifier, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Copy to Hash state (H starts as C mixed with identifier)
      State.Hash := State.Chaining;

      --  H = HASH(H || responder_static_public)
      Mix_Hash (State.Hash, Byte_Array (Peer.Static_Public), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Build message header
      --  msg.type = 1 (handshake initiation)
      Buffer (Buffer'First + Msg_Type_Offset) :=
        Transport.Msg_Type_Handshake_Initiation;

      --  msg.reserved = 0
      Buffer (Buffer'First + Reserved_Offset ..
              Buffer'First + Reserved_Offset + 2) := Reserved_Zero;

      --  msg.sender = local_index (little-endian)
      Buffer (Buffer'First + Sender_Offset ..
              Buffer'First + Sender_Offset + 3) := From_U32 (Local_Index);

      --  msg.ephemeral = ephemeral_public
      Buffer (Buffer'First + Ephemeral_Offset ..
              Buffer'First + Ephemeral_Offset + Transport.Key_Size - 1) :=
        Byte_Array (State.Ephemeral.Pub);

      --  C = KDF(C, ephemeral_public)
      --  H = HASH(H || ephemeral_public)
      Mix_Key (State.Chaining, Byte_Array (State.Ephemeral.Pub),
               Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      Mix_Hash (State.Hash, Byte_Array (State.Ephemeral.Pub), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: es = DH(ephemeral_secret, responder_static_public)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => State.Ephemeral.Sec,
         Their_Public => Peer.Static_Public,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, es)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Encrypt static public key: encrypted_static = AEAD(K, 0, s, H)
      --  Ciphertext goes into the buffer
      declare
         Static_Pub_Bytes : constant Byte_Array :=
           Byte_Array (Identity.Key_Pair.Pub);
         Ciphertext : Byte_Array
           (0 .. Transport.Encrypted_Static_Size - 1);
      begin
         Crypto.AEAD.Encrypt
           (Plaintext  => Static_Pub_Bytes,
            Ad         => State.Hash,
            Nonce      => Nonce,
            Key        => Temp_Key,
            Ciphertext => Ciphertext,
            Result     => Local_Status);

         if not Is_Success (Local_Status) then
            return;
         end if;

         Buffer (Buffer'First + Encrypted_Static_Offset ..
                 Buffer'First + Encrypted_Static_Offset +
                 Transport.Encrypted_Static_Size - 1) := Ciphertext;
      end;

      --  H = HASH(H || encrypted_static)
      Mix_Hash
        (State.Hash,
         Buffer (Buffer'First + Encrypted_Static_Offset ..
                 Buffer'First + Encrypted_Static_Offset +
                 Transport.Encrypted_Static_Size - 1),
         Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: ss = DH(static_secret, responder_static_public)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => Peer.Static_Public,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, ss)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Get current timestamp
      Crypto.TAI64N.Now (Timestamp);
      State.Last_Timestamp := Timestamp;

      --  Encrypt timestamp: encrypted_timestamp = AEAD(K, 0, timestamp, H)
      declare
         --  Get zero-copy access to timestamp bytes
         Timestamp_Ptr : constant Crypto.TAI64N.Timestamp_Bytes_Const_Access :=
           Crypto.TAI64N.To_Bytes (Timestamp);
         Ciphertext : Byte_Array
           (0 .. Transport.Encrypted_Timestamp_Size - 1);
      begin
         Crypto.AEAD.Encrypt
           (Plaintext  => Timestamp_Ptr.all,
            Ad         => State.Hash,
            Nonce      => Nonce,
            Key        => Temp_Key,
            Ciphertext => Ciphertext,
            Result     => Local_Status);

         if not Is_Success (Local_Status) then
            return;
         end if;

         Buffer (Buffer'First + Encrypted_Timestamp_Offset ..
                 Buffer'First + Encrypted_Timestamp_Offset +
                 Transport.Encrypted_Timestamp_Size - 1) := Ciphertext;
      end;

      --  H = HASH(H || encrypted_timestamp)
      Mix_Hash
        (State.Hash,
         Buffer (Buffer'First + Encrypted_Timestamp_Offset ..
                 Buffer'First + Encrypted_Timestamp_Offset +
                 Transport.Encrypted_Timestamp_Size - 1),
         Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Compute MAC1 = HASH(peer_mac1_key || msg[0..mac1_offset-1])
      declare
         Mac1 : Transport.Mac_Bytes;
      begin
         Compute_Mac
           (Key     => Peer.Mac1_Key,
            Message => Buffer (Buffer'First .. Buffer'First + Mac1_Offset - 1),
            Mac     => Mac1,
            Result  => Local_Status);

         if not Is_Success (Local_Status) then
            return;
         end if;

         Buffer (Buffer'First + Mac1_Offset ..
                 Buffer'First + Mac1_Offset + Transport.Mac_Size - 1) := Mac1;
      end;

      --  MAC2 = 0 (no cookie present)
      Buffer (Buffer'First + Mac2_Offset ..
              Buffer'First + Mac2_Offset + Transport.Mac_Size - 1) :=
        (others => 0);

      --  Update state
      State.Kind := State_Initiator_Sent;
      State.Role := Role_Initiator;

      --  Success!
      Result := (Success => True, Length => Transport.Handshake_Init_Size);
   end Create_Initiation;

   procedure Process_Initiation
     (Buffer   : Byte_Array;
      State    : out Handshake_State;
      Identity : Static_Identity;
      Result   : out Boolean)
   is
      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := (others => 0);

      --  Message field offsets (same as Create_Initiation)
      Msg_Type_Offset            : constant Natural := 0;
      Sender_Offset              : constant Natural := 4;
      Ephemeral_Offset           : constant Natural := 8;
      Encrypted_Static_Offset    : constant Natural :=
        Ephemeral_Offset + Transport.Key_Size;
      Encrypted_Timestamp_Offset : constant Natural :=
        Encrypted_Static_Offset + Transport.Encrypted_Static_Size;
      Mac1_Offset                : constant Natural :=
        Encrypted_Timestamp_Offset + Transport.Encrypted_Timestamp_Size;

      --  Decrypted values
      Decrypted_Static    : Byte_Array (0 .. Crypto.KX.Public_Key_Bytes - 1);
      Decrypted_Timestamp : Byte_Array
        (0 .. Crypto.TAI64N.Timestamp_Bytes_Length - 1);
      Computed_Mac        : Transport.Mac_Bytes;
   begin
      --  Initialize output
      State := Empty_Handshake;
      Result := False;

      --  Verify message type
      if Buffer (Buffer'First + Msg_Type_Offset) /=
         Transport.Msg_Type_Handshake_Initiation
      then
         return;
      end if;

      --  Extract sender index
      State.Remote_Index := To_U32
        (Buffer (Buffer'First + Sender_Offset ..
                 Buffer'First + Sender_Offset + 3));

      --  Extract initiator's ephemeral public key
      State.Remote_Ephemeral := Crypto.KX.Public_Key
        (Buffer (Buffer'First + Ephemeral_Offset ..
                 Buffer'First + Ephemeral_Offset + Transport.Key_Size - 1));

      --  Initialize Noise protocol state (same as initiator)
      --  C = HASH(Construction)
      Crypto.Blake2.Blake2s
        (Data   => Construction,
         Digest => State.Chaining,
         Result => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(C || Identifier)
      Mix_Hash (State.Chaining, Identifier, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      State.Hash := State.Chaining;

      --  H = HASH(H || responder_static_public)
      --  Note: We are the responder, so this is OUR static public
      Mix_Hash (State.Hash, Byte_Array (Identity.Key_Pair.Pub), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C = KDF(C, initiator_ephemeral)
      Mix_Key (State.Chaining, Byte_Array (State.Remote_Ephemeral),
               Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || initiator_ephemeral)
      Mix_Hash (State.Hash, Byte_Array (State.Remote_Ephemeral), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: es = DH(responder_static_secret, initiator_ephemeral)
      --  Note: We are responder, so we use OUR static secret
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => State.Remote_Ephemeral,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, es)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Decrypt initiator's static public key
      Crypto.AEAD.Decrypt
        (Ciphertext => Buffer (Buffer'First + Encrypted_Static_Offset ..
                               Buffer'First + Encrypted_Static_Offset +
                               Transport.Encrypted_Static_Size - 1),
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Plaintext  => Decrypted_Static,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         --  AEAD authentication failed - invalid message
         return;
      end if;

      State.Remote_Static := Crypto.KX.Public_Key (Decrypted_Static);

      --  H = HASH(H || encrypted_static)
      Mix_Hash
        (State.Hash,
         Buffer (Buffer'First + Encrypted_Static_Offset ..
                 Buffer'First + Encrypted_Static_Offset +
                 Transport.Encrypted_Static_Size - 1),
         Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: ss = DH(responder_static_secret, initiator_static)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => State.Remote_Static,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, ss)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Decrypt timestamp
      Crypto.AEAD.Decrypt
        (Ciphertext => Buffer (Buffer'First + Encrypted_Timestamp_Offset ..
                               Buffer'First + Encrypted_Timestamp_Offset +
                               Transport.Encrypted_Timestamp_Size - 1),
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Plaintext  => Decrypted_Timestamp,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         --  AEAD authentication failed
         return;
      end if;

      --  Store timestamp for replay protection
      --  TODO: Actually verify timestamp is newer than last seen
      --  Note: Timestamp is a private type matching the array layout,
      --  so we can use Unchecked_Conversion for zero-copy assignment.
      declare
         function To_Timestamp is new Ada.Unchecked_Conversion
           (Source => Byte_Array, Target => Crypto.TAI64N.Timestamp);
         Temp : constant Byte_Array
           (0 .. Crypto.TAI64N.Timestamp_Bytes_Length - 1) :=
           Decrypted_Timestamp;
      begin
         State.Last_Timestamp := To_Timestamp (Temp);
      end;

      --  H = HASH(H || encrypted_timestamp)
      Mix_Hash
        (State.Hash,
         Buffer (Buffer'First + Encrypted_Timestamp_Offset ..
                 Buffer'First + Encrypted_Timestamp_Offset +
                 Transport.Encrypted_Timestamp_Size - 1),
         Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Verify MAC1
      --  MAC1 = HASH(our_mac1_key || msg[0..mac1_offset-1])
      Compute_Mac
        (Key     => Identity.Mac1_Key,
         Message => Buffer (Buffer'First .. Buffer'First + Mac1_Offset - 1),
         Mac     => Computed_Mac,
         Result  => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Compare MACs (constant-time comparison would be better)
      if Computed_Mac /= Buffer (Buffer'First + Mac1_Offset ..
                                  Buffer'First + Mac1_Offset +
                                  Transport.Mac_Size - 1)
      then
         return;
      end if;

      --  MAC2 verification skipped (cookie system not implemented)

      --  Success - state is ready for Create_Response
      State.Role := Role_Responder;
      Result := True;
   end Process_Initiation;

   procedure Create_Response
     (Buffer   : in out Byte_Array;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Result   : out Response_Result)
   is
      pragma Unreferenced (Identity);  --  Not needed for Noise IK (no PSK)

      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;
      Local_Index  : Session_Index;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := (others => 0);

      --  Message field offsets for response message
      Msg_Type_Offset         : constant Natural := 0;
      Reserved_Offset         : constant Natural := 1;
      Sender_Offset           : constant Natural := 4;
      Receiver_Offset         : constant Natural := 8;
      Ephemeral_Offset        : constant Natural := 12;
      Encrypted_Empty_Offset  : constant Natural :=
        Ephemeral_Offset + Transport.Key_Size;
      Mac1_Offset             : constant Natural :=
        Encrypted_Empty_Offset + Transport.Encrypted_Empty_Size;
      Mac2_Offset             : constant Natural :=
        Mac1_Offset + Transport.Mac_Size;

      --  Empty payload for AEAD (Noise "empty" encryption)
      Empty_Payload : constant Byte_Array (1 .. 0) := (others => 0);
   begin
      --  Initialize result
      Result := (Success => False, Length => 0);

      --  Generate responder ephemeral keypair
      Crypto.KX.Generate_Key_Pair (State.Ephemeral, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Allocate local session index
      Local_Index := Allocate_Local_Index;
      State.Local_Index := Local_Index;

      --  Build message header
      --  msg.type = 2 (handshake response)
      Buffer (Buffer'First + Msg_Type_Offset) :=
        Transport.Msg_Type_Handshake_Response;

      --  msg.reserved = 0
      Buffer (Buffer'First + Reserved_Offset ..
              Buffer'First + Reserved_Offset + 2) := Reserved_Zero;

      --  msg.sender = our local_index (little-endian)
      Buffer (Buffer'First + Sender_Offset ..
              Buffer'First + Sender_Offset + 3) := From_U32 (Local_Index);

      --  msg.receiver = initiator's sender index
      Buffer (Buffer'First + Receiver_Offset ..
              Buffer'First + Receiver_Offset + 3) :=
        From_U32 (State.Remote_Index);

      --  msg.ephemeral = responder_ephemeral_public
      Buffer (Buffer'First + Ephemeral_Offset ..
              Buffer'First + Ephemeral_Offset + Transport.Key_Size - 1) :=
        Byte_Array (State.Ephemeral.Pub);

      --  C = KDF(C, responder_ephemeral)
      Mix_Key (State.Chaining, Byte_Array (State.Ephemeral.Pub),
               Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || responder_ephemeral)
      Mix_Hash (State.Hash, Byte_Array (State.Ephemeral.Pub), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: ee = DH(responder_ephemeral_secret, initiator_ephemeral)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => State.Ephemeral.Sec,
         Their_Public => State.Remote_Ephemeral,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, ee)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  DH: se = DH(responder_ephemeral_secret, initiator_static)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => State.Ephemeral.Sec,
         Their_Public => State.Remote_Static,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, K = KDF(C, se)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Encrypt empty payload: encrypted_empty = AEAD(K, 0, empty, H)
      --  This authenticates the handshake without sending additional data
      declare
         Ciphertext : Byte_Array (0 .. Transport.Encrypted_Empty_Size - 1);
      begin
         Crypto.AEAD.Encrypt
           (Plaintext  => Empty_Payload,
            Ad         => State.Hash,
            Nonce      => Nonce,
            Key        => Temp_Key,
            Ciphertext => Ciphertext,
            Result     => Local_Status);

         if not Is_Success (Local_Status) then
            return;
         end if;

         Buffer (Buffer'First + Encrypted_Empty_Offset ..
                 Buffer'First + Encrypted_Empty_Offset +
                 Transport.Encrypted_Empty_Size - 1) := Ciphertext;
      end;

      --  H = HASH(H || encrypted_empty)
      Mix_Hash
        (State.Hash,
         Buffer (Buffer'First + Encrypted_Empty_Offset ..
                 Buffer'First + Encrypted_Empty_Offset +
                 Transport.Encrypted_Empty_Size - 1),
         Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Compute MAC1 using initiator's static public key
      --  We need to compute the MAC1 key for the initiator
      declare
         Label_And_Public : Byte_Array
           (0 .. Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1);
         Initiator_Mac1_Key : Crypto.Blake2.Key_Buffer;
         Mac1 : Transport.Mac_Bytes;
      begin
         --  Compute initiator's MAC1 key: HASH(LABEL_MAC1 || initiator_static)
         Label_And_Public (0 .. Label_Mac1_Length - 1) := Label_Mac1;
         Label_And_Public (Label_Mac1_Length ..
                           Label_Mac1_Length + Crypto.KX.Public_Key_Bytes - 1)
           := Byte_Array (State.Remote_Static);

         Crypto.Blake2.Blake2s
           (Data   => Label_And_Public,
            Digest => Initiator_Mac1_Key,
            Result => Local_Status);
         if not Is_Success (Local_Status) then
            return;
         end if;

         Compute_Mac
           (Key     => Initiator_Mac1_Key,
            Message => Buffer (Buffer'First ..
                               Buffer'First + Mac1_Offset - 1),
            Mac     => Mac1,
            Result  => Local_Status);

         if not Is_Success (Local_Status) then
            return;
         end if;

         Buffer (Buffer'First + Mac1_Offset ..
                 Buffer'First + Mac1_Offset + Transport.Mac_Size - 1) := Mac1;
      end;

      --  MAC2 = 0 (no cookie present)
      Buffer (Buffer'First + Mac2_Offset ..
              Buffer'First + Mac2_Offset + Transport.Mac_Size - 1) :=
        (others => 0);

      --  Update state
      State.Kind := State_Responder_Sent;

      --  Success!
      Result := (Success => True, Length => Transport.Handshake_Response_Size);
   end Create_Response;

end Handshake;
