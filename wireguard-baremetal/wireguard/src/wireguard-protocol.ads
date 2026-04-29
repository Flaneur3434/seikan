--  Wireguard.Protocol - SPARK-Proven Protocol Core
--
--  All WireGuard protocol logic that can be formally verified lives here.
--  The parent Wireguard package is a thin C-facing shim that converts
--  C types (System.Address, access params, C.unsigned) to Ada types
--  and delegates to these operations.
--
--  State:
--    Protocol_State encompasses all mutable protocol data:
--      - My_Identity   (set once in Init, read thereafter)
--      - My_Peers      (per-peer config, set once in Init)
--      - HS_States     (per-peer handshake ephemeral state)
--      - Last_Init_Peer (remembers responder target for Create_Response)
--      - Last_Auto_Inits (per-peer rate-limit timestamps)
--      - Initialized flag

with Crypto.AEAD;
with Crypto.KX;
with Interfaces;
with Messages;
with Peer_Table;
with Session;
with Session.Timers;
with Session_Keys;
with Transport;
with Utils;
with WG_Types; use WG_Types;

package Wireguard.Protocol
  with SPARK_Mode => On, Abstract_State => Protocol_State
is
   pragma Unevaluated_Use_Of_Old (Allow);

   use type Messages.Packet_Length;

   ---------------------------------------------------------------------------
   --  Ghost helpers for postconditions
   ---------------------------------------------------------------------------

   --  TX buffer was successfully released to C: pointer is live,
   --  length is positive, one pool slot consumed.
   function TX_Sent
     (Ptr         : Utils.C_Buffer_Ptr;
      Len         : Messages.Packet_Length;
      Free_Before : Natural;
      Free_After  : Natural) return Boolean
   is (not Utils.Is_Null (Ptr) and then Len > 0
       and then Free_After = Free_Before - 1)
   with Ghost, Global => null;

   --  TX buffer was NOT released: pointer is null, length is zero,
   --  pool unchanged.
   function TX_Unsent
     (Ptr         : Utils.C_Buffer_Ptr;
      Len         : Messages.Packet_Length;
      Free_Before : Natural;
      Free_After  : Natural) return Boolean
   is (Utils.Is_Null (Ptr) and then Len = 0
       and then Free_After = Free_Before)
   with Ghost, Global => null;

   --  RX buffer was returned to pool: handle is null, one pool slot freed.
   function RX_Consumed
     (Handle_Null : Boolean;
      Free_Before : Natural;
      Free_After  : Natural) return Boolean
   is (Handle_Null and then Free_Before = Free_After - 1)
   with Ghost, Global => null;

   ---------------------------------------------------------------------------
   --  Protocol Initialization
   ---------------------------------------------------------------------------

   --  Per-peer configuration loaded from C (sdkconfig keys + AllowedIPs).
   type Peer_Init_Info is record
      Has_Key     : Boolean                  := False;
      Public_Key  : Crypto.KX.Public_Key     := [others => 0];
      Allowed_IP  : Peer_Table.IP_Prefix     := (Addr => 0, Prefix_Len => 0);
      Keepalive_S : Interfaces.Unsigned_64   := 0;
   end record;

   type Peer_Init_Array is array (Session.Peer_Index) of Peer_Init_Info;

   --  Initialize the protocol core from raw key material.
   --
   --  Derives public key, initializes identity and per-peer configs,
   --  registers public keys and AllowedIPs in Peer_Table, and sets
   --  persistent keepalive intervals in Session.
   --
   --  Peer 1 MUST have a valid key; peers 2+ are optional.
   --  On failure (bad key derivation, peer 1 missing): Success = False.
   procedure Init
     (Priv_Key : Crypto.KX.Secret_Key;
      Peers    : Peer_Init_Array;
      Success  : out Boolean)
   with
     Global =>
       (In_Out => (Protocol_State,
                   Peer_Table.Peer_State,
                   Session.Peer_States,
                   Session.Mutex_State)),
     Pre  => Session.Session_Ready,
     Post => Session.Session_Ready;

   ---------------------------------------------------------------------------
   --  Handshake TX — Build outgoing handshake messages
   ---------------------------------------------------------------------------

   --  Build a handshake initiation message for a peer (Initiator side).
   --
   --  Allocates a TX pool buffer, builds the Noise IK first message,
   --  copies it into the buffer, and releases the buffer to C.
   --
   procedure Create_Initiation
     (Peer    : Session.Peer_Index;
      TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   with
     Global =>
       (In_Out =>
          (Protocol_State,
           Messages.TX_Pool.Pool_State,
           Messages.TX_Pool.Borrow_State)),
     Post   =>
       (if Success
        then TX_Sent (TX_Ptr, TX_Len,
                      Messages.TX_Pool.Free_Count'Old,
                      Messages.TX_Pool.Free_Count)
        else TX_Unsent (TX_Ptr, TX_Len,
                        Messages.TX_Pool.Free_Count'Old,
                        Messages.TX_Pool.Free_Count));

   --  Build a handshake response message (Responder side).
   --
   --  Must be called after Handle_Initiation_RX returned
   --  Action_Send_Response.  Uses Last_Init_Peer (set by
   --  Handle_Initiation_RX) to find the correct handshake state.
   --
   --  Derives transport keys and activates the new session
   --  atomically after building the response.
   --
   procedure Create_Response
     (TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   with
     Global =>
       (In_Out =>
          (Protocol_State,
           Messages.TX_Pool.Pool_State,
           Messages.TX_Pool.Borrow_State,
           Session.Peer_States,
           Session.Mutex_State,
           Session_Keys.KP_State)),
     Pre    => Session.Session_Ready,
     Post   =>
       (if Success
        then TX_Sent (TX_Ptr, TX_Len,
                      Messages.TX_Pool.Free_Count'Old,
                      Messages.TX_Pool.Free_Count)
        else TX_Unsent (TX_Ptr, TX_Len,
                        Messages.TX_Pool.Free_Count'Old,
                        Messages.TX_Pool.Free_Count));

   ---------------------------------------------------------------------------
   --  Auto Handshake — Rate-limited handshake initiation
   ---------------------------------------------------------------------------

   --  Rate-limited handshake initiation for auto-init.
   --
   --  Called when inner data is queued but no session exists.
   --  Rate-limits to at most once per Rekey_Timeout_Ms (5 s) and
   --  skips if a handshake is already in flight for this peer.
   --
   --  On success: TX_Ptr/TX_Len point to wire-ready initiation buffer.
   --  On rate-limit/skip/error: TX_Ptr is null, TX_Len = 0.
   procedure Auto_Handshake
     (Peer   : Session.Peer_Index;
      TX_Ptr : out Utils.C_Buffer_Ptr;
      TX_Len : out Messages.Packet_Length)
   with
     Global =>
       (In_Out => (Protocol_State,
                   Messages.TX_Pool.Pool_State,
                   Messages.TX_Pool.Borrow_State));

   ---------------------------------------------------------------------------
   --  Transport TX — Build and encrypt data/keepalive packets
   ---------------------------------------------------------------------------

   --  Allocate a TX pool buffer, encrypt Payload (zero-length for
   --  keepalive), and release the buffer to C for transmission.
   --
   --  On success: TX_Ptr points to the wire-ready buffer, TX_Len > 0.
   --  On failure: TX_Ptr is null, TX_Len = 0.
   --
   --  Calls Session.Mark_Sent (resets keepalive timer).  The caller
   --  is responsible for calling Session.Mark_Data_Sent when Payload
   --  is non-empty (for unresponsive-peer detection, §6.5).
   procedure Build_And_Encrypt_TX
     (Peer    : Session.Peer_Index;
      Payload : Utils.Byte_Array;
      TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   with
     Global =>
       (In_Out =>
          (Messages.TX_Pool.Pool_State,
           Messages.TX_Pool.Borrow_State,
           Session.Peer_States,
           Session.Mutex_State)),
     Pre    =>
       Session.Session_Ready
       and then Payload'Length in 0 .. Transport.Max_Payload,
     Post   =>
       Session.Session_Ready
       and then
         (if Success
          then TX_Sent (TX_Ptr, TX_Len,
                        Messages.TX_Pool.Free_Count'Old,
                        Messages.TX_Pool.Free_Count)
          else TX_Unsent (TX_Ptr, TX_Len,
                          Messages.TX_Pool.Free_Count'Old,
                          Messages.TX_Pool.Free_Count));

   ---------------------------------------------------------------------------
   --  Timer Dispatch — Execute timer-triggered protocol actions
   ---------------------------------------------------------------------------

   --  Execute the protocol action triggered by a peer's timer tick.
   --
   --  Handles all Timer_Action values:
   --    No_Action        — no-op
   --    Send_Keepalive   — encrypts empty payload via Build_And_Encrypt_TX
   --    Session_Expired  — expires session
   --    Rekey_Timed_Out  — expires session
   --    Zero_All_Keys    — erases session + handshake state
   --    Initiate_Rekey   — sends handshake initiation
   --
   --  On Initiate_Rekey or Send_Keepalive: TX_Ptr/TX_Len may contain buffer.
   --  On all other arms:  TX_Ptr is null, TX_Len = 0.
   procedure Dispatch_Timer
     (Peer   : Session.Peer_Index;
      Action : Session.Timers.Timer_Action;
      TX_Ptr : out Utils.C_Buffer_Ptr;
      TX_Len : out Messages.Packet_Length)
   with
     Global =>
       (In_Out =>
          (Protocol_State,
           Messages.TX_Pool.Pool_State,
           Messages.TX_Pool.Borrow_State,
           Session.Peer_States,
           Session.Mutex_State)),
     Pre    => Session.Session_Ready,
     Post   =>
       Session.Session_Ready
       and then
         (if not Utils.Is_Null (TX_Ptr)
          then TX_Sent (TX_Ptr, TX_Len,
                        Messages.TX_Pool.Free_Count'Old,
                        Messages.TX_Pool.Free_Count)
          else TX_Unsent (TX_Ptr, TX_Len,
                          Messages.TX_Pool.Free_Count'Old,
                          Messages.TX_Pool.Free_Count));

   ---------------------------------------------------------------------------
   --  RX Dispatch — Unified receive dispatch
   ---------------------------------------------------------------------------

   --  Dispatch an incoming WireGuard packet by message type.
   --
   --  Acquires the RX buffer from C, reads the message kind, and
   --  delegates to the appropriate handler (Initiation, Response,
   --  Transport, Cookie).
   --
   --  Buffer lifecycle is fully managed internally:
   --    On RX_Decryption_Success: buffer released back to C via
   --      Release_RX_To_C.  PT_Len > 0.
   --    On all other results: buffer freed to pool.  PT_Len = 0.
   --
   procedure Dispatch_RX
     (RX_Ptr   : in out Utils.C_Buffer_Ptr;
      PT_Len   : out Messages.Packet_Length;
      Peer_Out : out Session.Peer_Index;
      Action   : out WG_Action)
   with
     Global =>
       (Input    => Peer_Table.Peer_State,
        In_Out   =>
          (Protocol_State,
           Messages.RX_Pool.Pool_State,
           Messages.RX_Pool.Borrow_State,
           Session.Peer_States,
           Session.Mutex_State,
           Session_Keys.KP_State)),
     Pre    =>
       not Utils.Is_Null (RX_Ptr)
       and then Session.Session_Ready,
     Post   =>
       Session.Session_Ready
       and then
         (if Action = RX_Decryption_Success
          then not Utils.Is_Null (RX_Ptr)
          else Utils.Is_Null (RX_Ptr));

   ---------------------------------------------------------------------------
   --  State Helpers (for callers that need narrow Protocol_State access)
   ---------------------------------------------------------------------------

   --  Clear handshake ephemeral state for a peer.
   --  Used by Dispatch_Timer on Zero_All_Keys action.
   procedure Clear_HS_State (Peer : Session.Peer_Index)
   with Global => (In_Out => Protocol_State);

end Wireguard.Protocol;
