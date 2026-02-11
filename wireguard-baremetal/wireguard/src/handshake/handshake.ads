--  Handshake - VeriGuard Noise IK Handshake Protocol
--
--  Implements the WireGuard Noise IK handshake pattern for key agreement.
--  This module owns all handshake state and orchestrates cryptographic
--  operations. C code never interprets handshake semantics.
--
--  TX Path (Initiator):
--    1. Ada allocates buffer from packet pool
--    2. Ada builds Message_Handshake_Initiation directly in buffer
--    3. Ada performs crypto operations (DH, AEAD encrypt)
--    4. Buffer is ready for transmission
--
--  Key Design Principles:
--    - "Ada is the brain, C is the hands"
--    - Zero-copy: build messages directly in pool buffers
--    - Single ownership: buffer handle tracks ownership
--    - SPARK-provable state transitions

with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.KX;
with Crypto.Blake2;
with Crypto.TAI64N;
with Messages;

package Handshake
  with SPARK_Mode => On
is
   use type Crypto.KX.Key_Pair;
   use type Crypto.KX.Public_Key;

   ---------------------
   --  Constants
   ---------------------

   --  Noise protocol construction identifier for WireGuard
   --  "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
   Construction_Length : constant := 37;

   --  Noise protocol identifier
   --  "WireGuard v1 zx2c4 Jason@zx2c4.com"
   Identifier_Length : constant := 34;

   --  Label for MAC1 key derivation
   Label_Mac1_Length : constant := 8;  --  "mac1----"

   ---------------------
   --  Handshake State
   ---------------------

   --  Chaining key for Noise protocol (32 bytes)
   subtype Chaining_Key is
     Byte_Array (0 .. Crypto.Blake2.BLAKE2S_OUTBYTES - 1);

   --  Hash state for Noise protocol (32 bytes)
   subtype Hash_State is Byte_Array (0 .. Crypto.Blake2.BLAKE2S_OUTBYTES - 1);

   --  Sender/Receiver index (local session identifier)
   subtype Session_Index is Unsigned_32;

   --  Handshake state machine
   type Handshake_Role is (Role_Initiator, Role_Responder);

   type Handshake_State_Kind is
     (State_Empty,            --  No handshake in progress
      State_Initiator_Sent,   --  Initiation sent, waiting for response
      State_Responder_Sent,   --  Response sent, waiting for first data
      State_Established);     --  Handshake complete, session keys derived

   --  Full handshake state
   --  Contains all ephemeral data needed during handshake
   type Handshake_State is record
      --  State machine
      Kind : Handshake_State_Kind;
      Role : Handshake_Role;

      --  Noise protocol state
      Chaining : Chaining_Key;
      Hash     : Hash_State;

      --  Our ephemeral keypair (generated per handshake)
      Ephemeral : Crypto.KX.Key_Pair;

      --  Remote peer's ephemeral public key (received in initiation/response)
      Remote_Ephemeral : Crypto.KX.Public_Key;

      --  Remote peer's static public key (decrypted from initiation)
      Remote_Static : Crypto.KX.Public_Key;

      --  Local sender index (identifies this session)
      Local_Index : Session_Index;

      --  Remote sender index (received in initiation/response)
      Remote_Index : Session_Index;

      --  Timestamp for replay protection (12-byte TAI64N)
      Last_Timestamp : Crypto.TAI64N.Timestamp;
   end record;

   --  Initial (empty) handshake state
   Empty_Handshake : constant Handshake_State;

   ---------------------
   --  Static Identity
   ---------------------

   --  Our long-term static identity keypair
   --  This persists across handshakes
   type Static_Identity is record
      Key_Pair : Crypto.KX.Key_Pair;
      --  Pre-computed MAC1 key = HASH(LABEL_MAC1 || static_public)
      Mac1_Key : Crypto.Blake2.Key_Buffer;
   end record;

   ---------------------
   --  Peer Configuration
   ---------------------

   --  Remote peer's static public key
   type Peer_Config is record
      Static_Public : Crypto.KX.Public_Key;
      --  Pre-computed MAC1 key for this peer = HASH(LABEL_MAC1 || peer_public)
      Mac1_Key      : Crypto.Blake2.Key_Buffer;
   end record;

   ---------------------
   --  Handshake Initiation Result
   ---------------------

   --  Result of building a handshake initiation message
   type Initiation_Result is record
      Success : Boolean;
      --  On success: length of message in buffer
      --  Message starts at buffer offset 0
      Length  : Natural;
   end record;

   --  Result of building a handshake response message
   type Response_Result is record
      Success : Boolean;
      --  On success: length of message in buffer
      Length  : Natural;
   end record;

   ---------------------
   --  Handshake Error Codes
   ---------------------

   --  Detailed error codes for Process_Initiation / Process_Response.
   --  Each value identifies a specific failure point.
   --  Use Handshake_Error'Pos (E) to get an integer for C-side logging.
   type Handshake_Error is
     (HS_OK,                  --   0: Success
      HS_Bad_Msg_Type,        --   1: Wrong message type byte
      HS_Mac1_Compute,        --   2: Failed to compute MAC1
      HS_Mac1_Mismatch,       --   3: MAC1 verification failed
      HS_Init_Chain,          --   4: HASH(Construction) failed
      HS_Init_Mix_Id,         --   5: HASH(C || Identifier) failed
      HS_Init_Mix_Spub,       --   6: HASH(H || static_public) failed
      HS_Mix_Ephem_CK,        --   7: KDF(C, ephemeral) failed
      HS_Mix_Ephem_H,         --   8: HASH(H || ephemeral) failed
      HS_DH_ES,               --   9: DH(es) failed
      HS_KDF_ES,              --  10: KDF(C, es) failed
      HS_Decrypt_Static,      --  11: AEAD decrypt static key failed
      HS_Mix_Enc_Static,      --  12: HASH(H || encrypted_static) failed
      HS_DH_SS,               --  13: DH(ss) failed
      HS_KDF_SS,              --  14: KDF(C, ss) failed
      HS_Decrypt_Timestamp,   --  15: AEAD decrypt timestamp failed
      HS_Mix_Enc_Ts,          --  16: HASH(H || encrypted_timestamp) failed
      HS_Receiver_Mismatch,   --  17: Receiver index mismatch
      HS_DH_EE,               --  18: DH(ee) failed
      HS_KDF_EE,              --  19: KDF(C, ee) failed
      HS_DH_SE,               --  20: DH(se) failed
      HS_KDF_SE,              --  21: KDF(C, se) failed
      HS_KDF_PSK,             --  22: KDF3(C, PSK) failed
      HS_Mix_Tau,             --  23: HASH(H || tau) failed
      HS_Decrypt_Empty,       --  24: AEAD decrypt empty failed
      HS_Mix_Enc_Empty);      --  25: HASH(H || encrypted_empty) failed

   ---------------------
   --  Procedures
   ---------------------

   --  Initialize static identity with a keypair
   --  Computes MAC1 key from static public key
   procedure Initialize_Identity
     (Identity : out Static_Identity;
      Key_Pair : Crypto.KX.Key_Pair;
      Result   : out Status)
   with
     Global => null,
     Post   => (if Is_Success (Result) then Identity.Key_Pair = Key_Pair);

   --  Initialize peer configuration
   --  Computes MAC1 key for the peer
   procedure Initialize_Peer
     (Peer        : out Peer_Config;
      Peer_Public : Crypto.KX.Public_Key;
      Result      : out Status)
   with
     Global => null,
     Post   => (if Is_Success (Result) then Peer.Static_Public = Peer_Public);

   --  Create a new handshake initiation message (TX path)
   --
   --  This is the first step of the handshake from the Initiator side.
   --  The message is built directly into the provided buffer for zero-copy.
   --
   --  Buffer must be at least Handshake_Init_Size bytes.
   --
   --  On success:
   --    - Buffer contains the complete Message_Handshake_Initiation
   --    - State is updated to State_Initiator_Sent
   --    - Result.Length contains the message length
   --
   --  Noise IK pattern (Initiator side, first message):
   --    -> e, es, s, ss
   --    e:  Generate ephemeral keypair
   --    es: DH(ephemeral_secret, responder_static)
   --    s:  Encrypt initiator static with current key
   --    ss: DH(initiator_static_secret, responder_static)
   procedure Create_Initiation
     (Msg      : out Messages.Message_Handshake_Initiation;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Peer     : Peer_Config;
      Result   : out Initiation_Result)
   with
     Post =>
       (if Result.Success
        then
          State.Kind = State_Initiator_Sent
          and then State.Role = Role_Initiator
          and then Result.Length = Messages.Handshake_Init_Size);

   --  Process a received handshake initiation message (RX path, Responder)
   --
   --  Validates and decrypts an incoming initiation message.
   --  On success, State contains the Noise protocol state needed to
   --  create a response.
   --
   --  Noise IK pattern (Responder side, receiving first message):
   --    <- e, es, s, ss
   --    e:  Read initiator ephemeral
   --    es: DH(responder_static_secret, initiator_ephemeral)
   --    s:  Decrypt initiator static
   --    ss: DH(responder_static_secret, initiator_static)
   procedure Process_Initiation
     (Msg      : Messages.Message_Handshake_Initiation;
      State    : out Handshake_State;
      Identity : Static_Identity;
      Result   : out Handshake_Error)
   with
     Global => null,
     Post   =>
       (if Result = HS_OK
        then State.Role = Role_Responder
        else State.Kind = State_Empty);

   --  Create a handshake response message (TX path, Responder)
   --
   --  Builds the response message directly into the provided buffer.
   --  Must be called after successful Process_Initiation.
   --
   --  Noise IK pattern (Responder side, second message):
   --    -> e, ee, se
   --    e:  Generate responder ephemeral
   --    ee: DH(responder_ephemeral_secret, initiator_ephemeral)
   --    se: DH(responder_ephemeral_secret, initiator_static)
   procedure Create_Response
     (Msg      : out Messages.Message_Handshake_Response;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Result   : out Response_Result)
   with
     Post =>
       (if Result.Success
        then
          State.Kind = State_Responder_Sent
          and then Result.Length = Messages.Handshake_Response_Size);

   --  Process a received handshake response message (RX path, Initiator)
   --
   --  Validates and decrypts an incoming response message.
   --  Must be called after successful Create_Initiation when
   --  State.Kind = State_Initiator_Sent.
   --
   --  Noise IK pattern (Initiator side, receiving second message):
   --    <- e, ee, se, psk
   --    e:  Read responder ephemeral
   --    ee: DH(initiator_ephemeral_secret, responder_ephemeral)
   --    se: DH(initiator_static_secret, responder_ephemeral)
   --    psk: Mix pre-shared key, decrypt empty payload
   procedure Process_Response
     (Msg      : Messages.Message_Handshake_Response;
      State    : in out Handshake_State;
      Identity : Static_Identity;
      Peer     : Peer_Config;
      Result   : out Handshake_Error)
   with
     Pre  => State.Kind = State_Initiator_Sent,
     Post =>
       (if Result = HS_OK
        then State.Kind = State_Established
        else State.Kind = State_Empty);

private

   Empty_Handshake : constant Handshake_State :=
     (Kind             => State_Empty,
      Role             => Role_Initiator,
      Chaining         => (others => 0),
      Hash             => (others => 0),
      Ephemeral        => (Pub => (others => 0), Sec => (others => 0)),
      Remote_Ephemeral => (others => 0),
      Remote_Static    => (others => 0),
      Local_Index      => 0,
      Remote_Index     => 0,
      Last_Timestamp   => Crypto.TAI64N.Zero);

end Handshake;
