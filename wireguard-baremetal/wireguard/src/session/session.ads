with Interfaces; use Interfaces;
with Utils;      use Utils;
with Handshake;
with Timer.Clock;
with Threads.Mutex;
with Session_Keys;

use type Handshake.Handshake_State_Kind;

package Session
  with SPARK_Mode => On, Abstract_State => (Peer_States, Mutex_State)
is

   ---------------------------------------------------------------------------
   --  Constants
   ---------------------------------------------------------------------------

   Max_Peers : constant := 2;

   --  Message counter limits (from whitepaper §5.4.6)
   --  Rekey_After_Messages  = 2^60  (initiate rekey after this many sends)
   --  Reject_After_Messages = 2^64 - 2^13 - 1  (hard drop limit)
   Rekey_After_Messages  : constant Unsigned_64 := 2 ** 60;
   Reject_After_Messages : constant Unsigned_64 := Unsigned_64'Last - 2 ** 13;

   --  WireGuard protocol timing constants (seconds)
   --  From whitepaper §6.1–6.4
   Rekey_After_Time_S   : constant Unsigned_64 := 120;
   Reject_After_Time_S  : constant Unsigned_64 := 180;
   Rekey_Attempt_Time_S : constant Unsigned_64 := 90;
   Rekey_Timeout_S      : constant Unsigned_64 := 5;
   Keepalive_Timeout_S  : constant Unsigned_64 := 10;

   ---------------------------------------------------------------------------
   --  Peer Index — Direct-mapped array index (1..Max_Peers)
   ---------------------------------------------------------------------------

   subtype Peer_Index is Positive range 1 .. Max_Peers;

   ---------------------------------------------------------------------------
   --  Backward-compatible keypair API (re-exported from Session_Keys)
   ---------------------------------------------------------------------------

   subtype Keypair is Session_Keys.Keypair;
   subtype Session_Key is Session_Keys.Session_Key;

   function Is_Valid (KP : Keypair) return Boolean
   renames Session_Keys.Is_Valid;
   function Send_Key (KP : Keypair) return Session_Key
   renames Session_Keys.Send_Key;
   function Receive_Key (KP : Keypair) return Session_Key
   renames Session_Keys.Receive_Key;
   function Receiver_Index (KP : Keypair) return Unsigned_32
   renames Session_Keys.Receiver_Index;

   ---------------------------------------------------------------------------
   --  Peer_State — limited private, visible only to child packages
   ---------------------------------------------------------------------------

   type Peer_State is limited private;

   ---------------------------------------------------------------------------
   --  Ghost state — bridges private Mtx into public contracts
   ---------------------------------------------------------------------------

   --  True after Init has been called.  Wraps Threads.Mutex.Is_Initialized
   --  on the private Mtx so public contracts can reference it.
   function Is_Mtx_Initialized return Boolean
   with Ghost;

   --  True while the session mutex is held.  Wraps Threads.Mutex.Is_Locked
   --  on the private Mtx so public contracts can reference lock state.
   function Is_Mtx_Locked return Boolean
   with Ghost;

   --  Structural invariant holds for all peer slots.
   --  Bridges the private Valid_Peer predicate into public contracts.
   function All_Peers_Valid return Boolean
   with Ghost, Global => (Input => Peer_States);

   --  Convenience bundle: mutex initialized, not locked, all peers valid.
   --  Reduces contract boilerplate on every public procedure.
   function Session_Ready return Boolean
   with Ghost,
        Global => (Input => (Peer_States, Mutex_State));

   ---------------------------------------------------------------------------
   --  Initialization
   ---------------------------------------------------------------------------

   --  Initialize the session table and mutex.
   --  Must be called once at startup before any session operations.
   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref)
   with Post => Session_Ready;

   ---------------------------------------------------------------------------
   --  Session lifecycle
   ---------------------------------------------------------------------------

   --  Atomic compound operation: derive transport keys from a completed
   --  handshake AND immediately promote the new keypair to Current.
   --
   --  Under a SINGLE lock:
   --    1. Derive_Keypair — KDF2 → send/receive keys → Next slot
   --    2. Activate_Next  — Previous ← Current ← Next, wipe old
   --    3. Wipe handshake ephemeral material (forward secrecy)
   --
   --  This avoids an atomicity gap: if derive and activate were
   --  separate public calls, the timer task could Expire_Session
   --  between them and wipe the freshly derived Next keypair.
   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with
     Global => (In_Out => (Peer_States, Mutex_State, Session_Keys.KP_State)),
     Pre  => Session_Ready,
     Post =>
       Session_Ready
       and then HS.Kind = Handshake.State_Empty;

   ---------------------------------------------------------------------------
   --  Session lookup
   ---------------------------------------------------------------------------

   --  Snapshot the current keypair for a peer into KP.
   --  KP is the sole snapshot — limited type prevents copies.
   procedure Get_Current (Peer : Peer_Index; KP : out Keypair)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre  => Session_Ready,
     Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   ---------------------------------------------------------------------------
   --  Send/Receive timestamp updates
   ---------------------------------------------------------------------------

   --  Record that we sent a packet to this peer.
   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   --  Record that we received a valid packet from this peer.
   procedure Mark_Received
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   --  Read and increment the current keypair's send counter.
   --  Returns the counter value BEFORE increment (used as nonce).
   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   --  Check the counter against the peer's current keypair replay filter.
   --  If valid, updates the filter to include this counter value.
   procedure Validate_And_Update_Replay
     (Peer    : Peer_Index;
      Counter : Unsigned_64;
      Accepted : out Boolean)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   ---------------------------------------------------------------------------
   --  Timer-driven session management
   --
   --  Called by the WG task in response to timer events.
   ---------------------------------------------------------------------------

   --  Wipe all three keypair slots for a peer.
   --  Called on Session_Expired and Rekey_Timed_Out.
   procedure Expire_Session (Peer : Peer_Index)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   --  Mark rekey in progress before sending initiation.
   procedure Set_Rekey_Flag
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready and then Now /= Timer.Clock.Never,
     Post => Session_Ready;

private

   type Peer_Mode is (Inactive, Established, Rekeying);

   type Peer_State is record
      --  Three session slots
      Current  : Session_Keys.Keypair;
      Previous : Session_Keys.Keypair;
      Next     : Session_Keys.Keypair;

      --  Packet timestamps (data path)
      Last_Sent      : Timer.Clock.Timestamp := Timer.Clock.Never;
      Last_Received  : Timer.Clock.Timestamp := Timer.Clock.Never;
      Last_Handshake : Timer.Clock.Timestamp := Timer.Clock.Never;

      --  Rekey timestamps (timer path)
      Rekey_Start     : Timer.Clock.Timestamp := Timer.Clock.Never;
      Rekey_Last_Sent : Timer.Clock.Timestamp := Timer.Clock.Never;

      Active : Boolean    := False;
      Mode   : Peer_Mode  := Inactive;
   end record;

   --  Structural invariant as a ghost predicate.
   --  We use an explicit function instead of Type_Invariant because
   --  SPARK does not assume Type_Invariant holds for package-level
   --  state on procedure entry — only for parameter values.
   --  With a ghost predicate we control exactly where the prover
   --  assumes (Pre) and must prove (Post) the invariant.
   function Valid_Peer (P : Peer_State) return Boolean is
     (case P.Mode is
        when Inactive    =>
          not P.Active or else not P.Current.Valid,
        when Established =>
          P.Active
          and then P.Current.Valid
          and then P.Rekey_Start = Timer.Clock.Never
          and then P.Rekey_Last_Sent = Timer.Clock.Never,
        when Rekeying    =>
          P.Active
          and then P.Current.Valid
          and then P.Rekey_Start /= Timer.Clock.Never)
   with Ghost;

   Peers : array (Peer_Index) of Peer_State := [others => <>]
   with Part_Of => Peer_States;

   Mtx : Threads.Mutex.Mutex_Handle
   with Part_Of => Mutex_State;

   function All_Peers_Valid return Boolean
   is (for all I in Peer_Index => Valid_Peer (Peers (I)));

   function Session_Ready return Boolean
   is (Is_Mtx_Initialized
       and then not Is_Mtx_Locked
       and then All_Peers_Valid);

   --  Ghost bridge completions
   function Is_Mtx_Initialized return Boolean
   is (Threads.Mutex.Is_Initialized (Mtx));

   function Is_Mtx_Locked return Boolean
   is (Threads.Mutex.Is_Locked (Mtx));

   procedure Lock
   with
     Global => (In_Out => Mutex_State),
     Pre    => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx),
     Post   => Is_Mtx_Initialized and then Threads.Mutex.Is_Locked (Mtx);

   procedure Unlock
   with
     Global => (In_Out => Mutex_State),
     Pre    => Is_Mtx_Initialized and then Threads.Mutex.Is_Locked (Mtx),
     Post   => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx);

   --  Promote Next → Current, Current → Previous, Previous → wiped.
   --  Post guarantees: Next slot is always cleared after rotation.
   --  If Next was invalid on entry, this is a no-op (still not Valid).
   --  Caller holds lock.
   procedure Activate_Next (Peer : Peer_Index)
   with
     Global => (In_Out => Peers),
     Pre    => All_Peers_Valid and then Peers (Peer).Next.Valid,
     Post   =>
       All_Peers_Valid
       and then not Peers (Peer).Next.Valid
       and then Peers (Peer).Mode = Established
       and then Peers (Peer).Last_Sent = Peers (Peer).Current.Created_At
       and then Peers (Peer).Last_Received = Peers (Peer).Current.Created_At;

end Session;
