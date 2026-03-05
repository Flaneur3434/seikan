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

with Messages;
with Peer_Table;
with Session;
with Session_Keys;
with WG_Types; use WG_Types;

package Wireguard.Protocol
  with SPARK_Mode     => On,
       Abstract_State => Protocol_State
is

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
        In_Out   => (Protocol_State,
                     Messages.RX_Pool.Pool_State),
        Proof_In => Messages.RX_Pool.Borrow_State),
     Pre  => not Messages.RX_Pool.Is_Null (RX_Handle)
              and then not Messages.RX_Pool.Is_Mutably_Borrowed (RX_Handle),
     Post =>
       Messages.RX_Pool.Is_Null (RX_Handle);
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
       (In_Out   => (Protocol_State,
                     Messages.RX_Pool.Pool_State,
                     Session.Peer_States,
                     Session.Mutex_State,
                     Session_Keys.KP_State),
        Proof_In => Messages.RX_Pool.Borrow_State),
     Pre  => not Messages.RX_Pool.Is_Null (RX_Handle)
              and then not Messages.RX_Pool.Is_Mutably_Borrowed (RX_Handle)
              and then Session.Session_Ready,
     Post =>
       Messages.RX_Pool.Is_Null (RX_Handle);
   --  Post: buffer is always freed (no leak)

end Wireguard.Protocol;
