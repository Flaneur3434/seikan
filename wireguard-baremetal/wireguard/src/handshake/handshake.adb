--  Handshake - VeriGuard Noise IK Handshake Protocol Implementation
--
--  Implements Noise IK handshake pattern for WireGuard-style key agreement.

with Crypto.Random;
with Crypto.AEAD;
with Crypto.KDF;
with Messages_Wire;
pragma Unreferenced (Messages_Wire);

package body Handshake
  with SPARK_Mode => On
is
   ---------------------
   --  Protocol Constants
   ---------------------

   --!format off

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
   Reserved_Zero : constant Messages.Reserved_Bytes := [others => 0];

   --!format on

   --  Pre-shared symmetric key placeholder.
   --  When no PSK is configured, Q = 0^32 (32 zero bytes).
   --  The KDF3 step is still performed per the Noise IKpsk2 pattern.
   No_PSK : constant Byte_Array (0 .. 31) := [others => 0];

   ---------------------
   --  Random Session Index Generation
   ---------------------

   --  Generate a random session index per the WireGuard spec (Section 5.4.2):
   --    I_i <- random()
   --  Random indices prevent correlation of handshakes by observers.

   procedure Allocate_Local_Index (Index : out Session_Index)
     with Global => null;

   procedure Allocate_Local_Index (Index : out Session_Index) is
      Random_Bytes : Bytes_4;
   begin
      Crypto.Random.Fill_Random (Random_Bytes);
      Index := To_U32 (Random_Bytes);
   end Allocate_Local_Index;

   ---------------------
   --  Noise Protocol Helpers
   ---------------------

   --  MixHash: H = HASH(H || data)
   --  Thin wrapper over the 4-param version; uses a temp to avoid aliasing.
   procedure Mix_Hash
     (H      : in out Hash_State;
      Data   : Byte_Array;
      Result : out Status)
   with
     SPARK_Mode => On,
     Global     => null;

   --  MixHash (separate output): Output = HASH(Input || data)
   procedure Mix_Hash
     (Input  : Hash_State;
      Data   : Byte_Array;
      Output : out Hash_State;
      Result : out Status)
   with
     SPARK_Mode => On,
     Global     => null
   is
      State       : aliased Crypto.Blake2.Blake2s_State;
      Local_Result : Status;
   begin
      Crypto.Blake2.Blake2s_Init
        (Outlen => Crypto.Blake2.BLAKE2S_OUTBYTES,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         Output := [others => 0];
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => Input,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         Output := [others => 0];
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => Data,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Result := Local_Result;
         Output := [others => 0];
         return;
      end if;

      Crypto.Blake2.Blake2s_Final
        (State  => State,
         Digest => Output,
         Result => Result);
   end Mix_Hash;

   --  MixHash body (defined after 4-param overload so it can call it)
   procedure Mix_Hash
     (H      : in out Hash_State;
      Data   : Byte_Array;
      Result : out Status)
   is
      Temp : Hash_State;
   begin
      Mix_Hash (H, Data, Temp, Result);
      if Is_Success (Result) then
         H := Temp;
      end if;
   end Mix_Hash;

   --  KDF1: C = KDF(C, input) — chaining key update only
   procedure Mix_Key
     (C      : in out Chaining_Key;
      Input  : Byte_Array;
      Result : out Status)
   with
     SPARK_Mode => On,
     Global     => null
   is
      New_C : Crypto.KDF.KDF_Key;
   begin
      Crypto.KDF.KDF1 (C, Input, New_C, Result);
      if Is_Success (Result) then
         C := New_C;
      end if;
   end Mix_Key;

   --  KDF2: (C, K) = KDF(C, input)
   procedure Mix_Key
     (C      : in out Chaining_Key;
      Input  : Byte_Array;
      K      : out Crypto.AEAD.Key_Buffer;
      Result : out Status)
   with
     SPARK_Mode => On,
     Global     => null
   is
      New_C : Crypto.KDF.KDF_Key;
   begin
      Crypto.KDF.KDF2 (C, Input, New_C, K, Result);
      if Is_Success (Result) then
         C := New_C;
      else
         K := [others => 0];
      end if;
   end Mix_Key;

   --  KDF3: (C, Tau, K) = KDF(C, input)
   --  Three-output KDF for PSK mixing (Noise IKpsk2 pattern).
   procedure Mix_Key
     (C      : in out Chaining_Key;
      Input  : Byte_Array;
      Tau    : out Hash_State;
      K      : out Crypto.AEAD.Key_Buffer;
      Result : out Status)
   with
     SPARK_Mode => On,
     Global     => null
   is
      New_C : Crypto.KDF.KDF_Key;
   begin
      Crypto.KDF.KDF3 (C, Input, New_C, Tau, K, Result);
      if Is_Success (Result) then
         C := New_C;
      else
         Tau := [others => 0];
         K := [others => 0];
      end if;
   end Mix_Key;

   --  Mac(key, input) = Keyed-Blake2s-128
   --  Per the whitepaper: native 16-byte output, NOT truncation of 32.
   --  BLAKE2s mixes digest_length into its parameter block, so
   --  Blake2s(key, msg, outlen=16) ≠ Blake2s(key, msg, outlen=32)[0..15].
   procedure Compute_Mac
     (Key     : Crypto.Blake2.Key_Buffer;
      Message : Byte_Array;
      Mac     : out Messages.Mac_Bytes;
      Result  : out Status)
   with
     SPARK_Mode => On,
     Global     => null
   is
      State        : aliased Crypto.Blake2.Blake2s_State;
      Local_Result : Status;
   begin
      Crypto.Blake2.Blake2s_Init_Key
        (Key    => Key,
         Outlen => Messages.Mac_Size,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Mac := [others => 0];
         Result := Local_Result;
         return;
      end if;

      Crypto.Blake2.Blake2s_Update
        (Data   => Message,
         State  => State,
         Result => Local_Result);
      if not Is_Success (Local_Result) then
         Mac := [others => 0];
         Result := Local_Result;
         return;
      end if;

      Crypto.Blake2.Blake2s_Final
        (State  => State,
         Digest => Mac,
         Result => Result);
      if not Is_Success (Result) then
         Mac := [others => 0];
      end if;
   end Compute_Mac;

   ---------------------
   --  Public Procedures
   ---------------------

   procedure Initialize_Identity
     (Key_Pair : Crypto.KX.Key_Pair;
      Result   : out Identity_Result.Result)
   is
      Local_Status : Status;
      Id           : Static_Identity;
   begin
      Id.Key_Pair := Key_Pair;

      --  Compute MAC1 key: HASH(LABEL_MAC1 || static_public)
      Crypto.Blake2.Blake2s
        (Data   => Label_Mac1 & Byte_Array (Key_Pair.Pub),
         Digest => Id.Mac1_Key,
         Result => Local_Status);
      if Is_Success (Local_Status) then
         Result := Identity_Result.Ok (Id);
      else
         Result := Identity_Result.Err (HS_Mac1_Compute);
      end if;
   end Initialize_Identity;

   procedure Initialize_Peer
     (Peer_Public : Crypto.KX.Public_Key;
      Result      : out Peer_Result.Result)
   is
      Local_Status : Status;
      P            : Peer_Config;
   begin
      P.Static_Public := Peer_Public;

      --  Compute MAC1 key: HASH(LABEL_MAC1 || peer_public)
      Crypto.Blake2.Blake2s
        (Data   => Label_Mac1 & Byte_Array (Peer_Public),
         Digest => P.Mac1_Key,
         Result => Local_Status);
      if Is_Success (Local_Status) then
         Result := Peer_Result.Ok (P);
      else
         Result := Peer_Result.Err (HS_Mac1_Compute);
      end if;
   end Initialize_Peer;

   procedure Create_Initiation
     (Msg      : out Messages.Message_Handshake_Initiation;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Peer     : Peer_Config;
      Result   : out HS_Result.Result)
   is
      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := [others => 0];
   begin
      --  Initialize outputs
      Msg := (Msg_Type            => 0,
              Reserved            => [others => 0],
              Sender              => [others => 0],
              Ephemeral           => [others => 0],
              Encrypted_Static    => [others => 0],
              Encrypted_Timestamp => [others => 0],
              Mac1                => [others => 0],
              Mac2                => [others => 0]);
      Result := HS_Result.Err (HS_Failed);

      --  Allocate local session index
      Allocate_Local_Index (State.Local_Index);

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
      Mix_Hash (State.Chaining, Identifier, State.Hash, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || responder_static_public)
      Mix_Hash (State.Hash, Byte_Array (Peer.Static_Public), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Generate ephemeral keypair
      Crypto.KX.Generate_Key_Pair (State.Ephemeral, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Build message header
      Msg.Msg_Type  := Messages.Msg_Type_Handshake_Initiation;
      Msg.Reserved  := Reserved_Zero;
      Msg.Sender    := From_U32 (State.Local_Index);
      Msg.Ephemeral := State.Ephemeral.Pub;

      --  C = KDF(C, ephemeral_public)
      Mix_Key (State.Chaining, Byte_Array (State.Ephemeral.Pub),
               Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || ephemeral_public)
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
      Crypto.AEAD.Encrypt
        (Plaintext  => Byte_Array (Identity.Key_Pair.Pub),
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Ciphertext => Msg.Encrypted_Static,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || encrypted_static)
      Mix_Hash (State.Hash, Msg.Encrypted_Static, Local_Status);
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
      Crypto.TAI64N.Now (State.Last_Timestamp);

      --  Encrypt timestamp: encrypted_timestamp = AEAD(K, 0, timestamp, H)
      Crypto.AEAD.Encrypt
        (Plaintext  => Byte_Array (State.Last_Timestamp),
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Ciphertext => Msg.Encrypted_Timestamp,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || encrypted_timestamp)
      Mix_Hash (State.Hash, Msg.Encrypted_Timestamp, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Compute MAC1 = MAC(peer_mac1_key || msg[0..mac1_offset-1])
      Compute_Mac
        (Key     => Peer.Mac1_Key,
         Message => Messages.To_Mac1_Prefix (Msg),
         Mac     => Msg.Mac1,
         Result  => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  MAC2 = 0 (no cookie present, already zeroed)

      --  Update state machine
      State.Kind := State_Initiator_Sent;
      State.Role := Role_Initiator;

      Result := HS_Result.Ok (Messages.Handshake_Init_Size);
   end Create_Initiation;

   procedure Process_Initiation
     (Msg      : Messages.Message_Handshake_Initiation;
      State    : out Handshake_State;
      Identity : Static_Identity;
      Result   : out HS_Result.Result)
   is
      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := [others => 0];

      --  Decrypted values
      Decrypted_Static    : Byte_Array (0 .. Crypto.KX.Public_Key_Bytes - 1);
      Decrypted_Timestamp : Crypto.TAI64N.Timestamp;
      Computed_Mac        : Messages.Mac_Bytes;
   begin
      --  Initialize output
      State := Empty_Handshake;

      --  Verify message type
      if Msg.Msg_Type /= Messages.Msg_Type_Handshake_Initiation then
         Result := HS_Result.Err (HS_Bad_Msg_Type);
         return;
      end if;

      --  Verify MAC1 first (cheap DoS filter before expensive crypto)
      Compute_Mac
        (Key     => Identity.Mac1_Key,
         Message => Messages.To_Mac1_Prefix (Msg),
         Mac     => Computed_Mac,
         Result  => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mac1_Compute);
         return;
      end if;

      if Computed_Mac /= Msg.Mac1 then
         Result := HS_Result.Err (HS_Mac1_Mismatch);
         return;
      end if;

      --  Extract sender index
      State.Remote_Index := To_U32 (Msg.Sender);

      --  Extract initiator's ephemeral public key
      State.Remote_Ephemeral := Msg.Ephemeral;

      --  Initialize Noise protocol state
      --  C = HASH(Construction)
      Crypto.Blake2.Blake2s
        (Data   => Construction,
         Digest => State.Chaining,
         Result => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Init_Chain);
         return;
      end if;

      --  H = HASH(C || Identifier)
      Mix_Hash (State.Chaining, Identifier, State.Hash, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Init_Mix_Id);
         return;
      end if;

      --  H = HASH(H || responder_static_public)
      Mix_Hash (State.Hash, Byte_Array (Identity.Key_Pair.Pub), Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Init_Mix_Spub);
         return;
      end if;

      --  C = KDF(C, initiator_ephemeral)
      Mix_Key (State.Chaining, Byte_Array (State.Remote_Ephemeral),
               Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Ephem_CK);
         return;
      end if;

      --  H = HASH(H || initiator_ephemeral)
      Mix_Hash (State.Hash, Byte_Array (State.Remote_Ephemeral), Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Ephem_H);
         return;
      end if;

      --  DH: es = DH(responder_static_secret, initiator_ephemeral)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => State.Remote_Ephemeral,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_DH_ES);
         return;
      end if;

      --  C, K = KDF(C, es)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_KDF_ES);
         return;
      end if;

      --  Decrypt initiator's static public key

      Crypto.AEAD.Decrypt
        (Ciphertext => Msg.Encrypted_Static,
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Plaintext  => Decrypted_Static,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Decrypt_Static);
         return;
      end if;

      State.Remote_Static := Crypto.KX.Public_Key (Decrypted_Static);

      --  H = HASH(H || encrypted_static)
      Mix_Hash (State.Hash, Msg.Encrypted_Static, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Enc_Static);
         return;
      end if;

      --  DH: ss = DH(responder_static_secret, initiator_static)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => State.Remote_Static,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_DH_SS);
         return;
      end if;

      --  C, K = KDF(C, ss)
      Mix_Key (State.Chaining, Byte_Array (Shared), Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_KDF_SS);
         return;
      end if;

      --  Decrypt timestamp
      Crypto.AEAD.Decrypt
        (Ciphertext => Msg.Encrypted_Timestamp,
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Plaintext  => Decrypted_Timestamp,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Decrypt_Timestamp);
         return;
      end if;

      --  Store timestamp for replay protection
      State.Last_Timestamp := Decrypted_Timestamp;

      --  H = HASH(H || encrypted_timestamp)
      Mix_Hash (State.Hash, Msg.Encrypted_Timestamp, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Enc_Ts);
         return;
      end if;

      --  MAC2 verification skipped (cookie system not implemented)

      --  Success - update state machine
      State.Role := Role_Responder;
      Result := HS_Result.Ok (0);
   end Process_Initiation;

   procedure Create_Response
     (Msg      : out Messages.Message_Handshake_Response;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Result   : out HS_Result.Result)
   is
      pragma Unreferenced (Identity);

      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;
      Tau          : Hash_State;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := [others => 0];

      --  Empty payload for AEAD (Noise "empty" encryption)
      Empty_Payload : constant Byte_Array (1 .. 0) := [others => 0];
   begin
      --  Initialize outputs
      Msg := (Msg_Type        => 0,
              Reserved        => [others => 0],
              Sender          => [others => 0],
              Receiver        => [others => 0],
              Ephemeral       => [others => 0],
              Encrypted_Empty => [others => 0],
              Mac1            => [others => 0],
              Mac2            => [others => 0]);
      Result := HS_Result.Err (HS_Failed);

      --  Generate responder ephemeral keypair
      Crypto.KX.Generate_Key_Pair (State.Ephemeral, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Allocate local session index
      Allocate_Local_Index (State.Local_Index);

      --  Build message header
      Msg.Msg_Type  := Messages.Msg_Type_Handshake_Response;
      Msg.Reserved  := Reserved_Zero;
      Msg.Sender    := From_U32 (State.Local_Index);
      Msg.Receiver  := From_U32 (State.Remote_Index);
      Msg.Ephemeral := State.Ephemeral.Pub;

      --  C = KDF(C, responder_ephemeral)
      Mix_Key (State.Chaining, Byte_Array (State.Ephemeral.Pub),
               Local_Status);
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

      --  C = KDF1(C, ee)
      Mix_Key (State.Chaining, Byte_Array (Shared), Local_Status);
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

      --  C = KDF1(C, se)
      Mix_Key (State.Chaining, Byte_Array (Shared), Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  C, τ, K = KDF3(C, Q) — PSK mixing (Q = 0^32, no PSK configured)
      Mix_Key (State.Chaining, No_PSK, Tau, Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || τ)
      Mix_Hash (State.Hash, Tau, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Encrypt empty payload: encrypted_empty = AEAD(K, 0, empty, H)
      Crypto.AEAD.Encrypt
        (Plaintext  => Empty_Payload,
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Ciphertext => Msg.Encrypted_Empty,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  H = HASH(H || encrypted_empty)
      Mix_Hash (State.Hash, Msg.Encrypted_Empty, Local_Status);
      if not Is_Success (Local_Status) then
         return;
      end if;

      --  Compute MAC1 using initiator's static public key
      declare
         Initiator_Mac1_Key : Crypto.Blake2.Key_Buffer;
      begin
         --  Compute initiator's MAC1 key: HASH(LABEL_MAC1 || initiator_static)
         Crypto.Blake2.Blake2s
           (Data   => Label_Mac1 & Byte_Array (State.Remote_Static),
            Digest => Initiator_Mac1_Key,
            Result => Local_Status);
         if not Is_Success (Local_Status) then
            return;
         end if;

         Compute_Mac
           (Key     => Initiator_Mac1_Key,
            Message => Messages.To_Mac1_Prefix (Msg),
            Mac     => Msg.Mac1,
            Result  => Local_Status);
         if not Is_Success (Local_Status) then
            return;
         end if;
      end;

      --  MAC2 = 0 (already zeroed)

      --  Update state machine
      State.Kind := State_Responder_Sent;

      Result := HS_Result.Ok (Messages.Handshake_Response_Size);
   end Create_Response;

   procedure Process_Response
     (Msg      : Messages.Message_Handshake_Response;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Peer     : Peer_Config;
      Result   : out HS_Result.Result)
   is
      pragma Unreferenced (Peer);

      Local_Status : Status;
      Temp_Key     : Crypto.AEAD.Key_Buffer;
      Shared       : Crypto.KX.Shared_Secret;
      Tau          : Hash_State;

      --  Noise protocol uses nonce=0 for all handshake AEAD operations.
      Nonce : constant Crypto.AEAD.Nonce_Buffer := [others => 0];

      --  Decrypted empty payload (should be zero-length after stripping tag)
      Decrypted_Empty : Byte_Array (1 .. 0);
      Computed_Mac     : Messages.Mac_Bytes;
   begin
      --  Verify message type
      if Msg.Msg_Type /= Messages.Msg_Type_Handshake_Response then
         Result := HS_Result.Err (HS_Bad_Msg_Type);
         State := Empty_Handshake;
         return;
      end if;

      --  Verify receiver index matches our local index
      if To_U32 (Msg.Receiver) /= State.Local_Index then
         Result := HS_Result.Err (HS_Receiver_Mismatch);
         State := Empty_Handshake;
         return;
      end if;

      --  Verify MAC1 using our own MAC1 key (keyed to our static public)
      Compute_Mac
        (Key     => Identity.Mac1_Key,
         Message => Messages.To_Mac1_Prefix (Msg),
         Mac     => Computed_Mac,
         Result  => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mac1_Compute);
         State := Empty_Handshake;
         return;
      end if;

      if Computed_Mac /= Msg.Mac1 then
         Result := HS_Result.Err (HS_Mac1_Mismatch);
         State := Empty_Handshake;
         return;
      end if;

      --  Extract sender index
      State.Remote_Index := To_U32 (Msg.Sender);

      --  Extract responder's ephemeral public key
      State.Remote_Ephemeral := Msg.Ephemeral;

      --  C = KDF1(C, responder_ephemeral)
      Mix_Key (State.Chaining, Byte_Array (State.Remote_Ephemeral),
               Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Ephem_CK);
         State := Empty_Handshake;
         return;
      end if;

      --  H = HASH(H || responder_ephemeral)
      Mix_Hash (State.Hash, Byte_Array (State.Remote_Ephemeral), Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Ephem_H);
         State := Empty_Handshake;
         return;
      end if;

      --  DH: ee = DH(initiator_ephemeral_secret, responder_ephemeral)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => State.Ephemeral.Sec,
         Their_Public => State.Remote_Ephemeral,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_DH_EE);
         State := Empty_Handshake;
         return;
      end if;

      --  C = KDF1(C, ee)
      Mix_Key (State.Chaining, Byte_Array (Shared), Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_KDF_EE);
         State := Empty_Handshake;
         return;
      end if;

      --  DH: se = DH(initiator_static_secret, responder_ephemeral)
      Crypto.KX.DH
        (Shared       => Shared,
         My_Secret    => Identity.Key_Pair.Sec,
         Their_Public => State.Remote_Ephemeral,
         Result       => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_DH_SE);
         State := Empty_Handshake;
         return;
      end if;

      --  C = KDF1(C, se)
      Mix_Key (State.Chaining, Byte_Array (Shared), Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_KDF_SE);
         State := Empty_Handshake;
         return;
      end if;

      --  C, τ, K = KDF3(C, Q) — PSK mixing (Q = 0^32, no PSK configured)
      Mix_Key (State.Chaining, No_PSK, Tau, Temp_Key, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_KDF_PSK);
         State := Empty_Handshake;
         return;
      end if;

      --  H = HASH(H || τ)
      Mix_Hash (State.Hash, Tau, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Tau);
         State := Empty_Handshake;
         return;
      end if;

      --  Decrypt empty payload: AEAD-Decrypt(K, 0, encrypted_empty, H)
      Crypto.AEAD.Decrypt
        (Ciphertext => Msg.Encrypted_Empty,
         Ad         => State.Hash,
         Nonce      => Nonce,
         Key        => Temp_Key,
         Plaintext  => Decrypted_Empty,
         Result     => Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Decrypt_Empty);
         State := Empty_Handshake;
         return;
      end if;

      --  H = HASH(H || encrypted_empty)
      Mix_Hash (State.Hash, Msg.Encrypted_Empty, Local_Status);
      if not Is_Success (Local_Status) then
         Result := HS_Result.Err (HS_Mix_Enc_Empty);
         State := Empty_Handshake;
         return;
      end if;

      --  MAC2 verification skipped (cookie system not implemented)

      --  Success - update state machine
      State.Kind := State_Established;
      Result := HS_Result.Ok (0);
   end Process_Response;

end Handshake;
