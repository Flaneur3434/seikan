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

with Handshake;
with Messages;
with Peer_Table;
with Session;
with Session_Keys;
with Utils;
with WG_Types; use WG_Types;

package Wireguard.Protocol
  with SPARK_Mode => On, Abstract_State => Protocol_State
is
   use type Messages.Packet_Length;

   ---------------------------------------------------------------------------
   --  Handshake RX — Process incoming handshake messages
   --
   --  These are the first functions moved into the proven core.
   --  They take Ada-typed buffer handles (no System.Address, no access),
   --  perform protocol logic, and return a WG_Action.
   ---------------------------------------------------------------------------

   --  Process a received handshake initiation (Responder side).
   --
   --  Reads the message from the RX buffer, processes the Noise IK
   --  first message, identifies the peer via static-key lookup,
   --  and stores handshake state for Create_Response.
   --
   --  RX buffer is always freed (consumed) by this function.
   --  On success: Peer_Out = identified peer, returns Action_Send_Response.
   --  On failure: returns Action_Error.
   procedure Handle_Initiation_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      Peer_Out  : out Session.Peer_Index;
      Action    : out WG_Action)
   with
     Global =>
       (Input    => (Peer_Table.Peer_State),
        In_Out   => (Protocol_State, Messages.RX_Pool.Pool_State),
        Proof_In => Messages.RX_Pool.Borrow_State),
     Pre    =>
       not Messages.RX_Pool.Is_Null (RX_Handle)
       and then not Messages.RX_Pool.Is_Mutably_Borrowed (RX_Handle),
     Post   => Messages.RX_Pool.Is_Null (RX_Handle);
   --  Post: buffer is always freed (no leak)

   --  Process a received handshake response (Initiator side).
   --
   --  Reads the message from the RX buffer, identifies the peer by
   --  matching receiver_index against pending handshake states,
   --  processes the Noise IK second message, and derives transport keys.
   --
   --  RX buffer is always freed (consumed) by this function.
   --  On success: Peer_Out = identified peer, returns Action_None.
   --  On failure: returns Action_Error.
   procedure Handle_Response_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      Peer_Out  : out Session.Peer_Index;
      Action    : out WG_Action)
   with
     Global =>
       (In_Out   =>
          (Protocol_State,
           Messages.RX_Pool.Pool_State,
           Session.Peer_States,
           Session.Mutex_State,
           Session_Keys.KP_State),
        Proof_In => Messages.RX_Pool.Borrow_State),
     Pre    =>
       not Messages.RX_Pool.Is_Null (RX_Handle)
       and then not Messages.RX_Pool.Is_Mutably_Borrowed (RX_Handle)
       and then Session.Session_Ready,
     Post   => Messages.RX_Pool.Is_Null (RX_Handle);
   --  Post: buffer is always freed (no leak)

   ---------------------------------------------------------------------------
   --  Protocol Initialization (bridge until Init moves to Protocol)
   ---------------------------------------------------------------------------

   type Peer_Config_Array is
     array (Session.Peer_Index) of Handshake.Peer_Config;

   --  Copy identity and peer configs into Protocol's state.
   --  Called by wireguard.adb.Init after setting up the handshake material.
   procedure Init_Protocol
     (Identity : Handshake.Static_Identity; Peers : Peer_Config_Array)
   with Global => (Output => Protocol_State);

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
        then not Utils.Is_Null (TX_Ptr) and then TX_Len > 0
        else Utils.Is_Null (TX_Ptr) and then TX_Len = 0);

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
        then not Utils.Is_Null (TX_Ptr) and then TX_Len > 0
        else Utils.Is_Null (TX_Ptr) and then TX_Len = 0);

   ---------------------------------------------------------------------------
   --  Auto Handshake — Rate-limited handshake initiation
   ---------------------------------------------------------------------------

   --  Rate-limited handshake initiation for auto-init.
   --
   --  Called when inner data is queued but no session exists.
   --  Rate-limits to at most once per Rekey_Timeout_S (5 s) and
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
   --  State Helpers (for callers that need narrow Protocol_State access)
   ---------------------------------------------------------------------------

   --  Clear handshake ephemeral state for a peer.
   --  Used by Dispatch_Timer on Zero_All_Keys action.
   procedure Clear_HS_State (Peer : Session.Peer_Index)
   with Global => (In_Out => Protocol_State);

end Wireguard.Protocol;
