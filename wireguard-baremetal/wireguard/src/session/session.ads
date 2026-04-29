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

   --  WireGuard protocol timing constants (milliseconds)
   --  From whitepaper §6.1–6.4
   Rekey_After_Time_Ms   : constant Unsigned_64 := 120 * 1_000;
   Reject_After_Time_Ms  : constant Unsigned_64 := 180 * 1_000;
   Rekey_Attempt_Time_Ms : constant Unsigned_64 :=  90 * 1_000;
   Rekey_Timeout_Ms      : constant Unsigned_64 :=   5 * 1_000;
   Keepalive_Timeout_Ms  : constant Unsigned_64 :=  10 * 1_000;

   --  §6.3: erase all keys after 3×Reject_After_Time (540 s)
   Key_Zeroing_After_Ms  : constant Unsigned_64 := 3 * Reject_After_Time_Ms;

   --  §6.5: unresponsive peer detection threshold (15 s)
   New_Handshake_Time_Ms : constant Unsigned_64 :=
     Keepalive_Timeout_Ms + Rekey_Timeout_Ms;

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

   --  True when the peer's session is in the Established state.
   --  Bridges the private Peer_Mode into public contracts so callers
   --  can express postconditions that depend on session activation.
   function Is_Peer_Established (Peer : Peer_Index) return Boolean
   with Ghost, Global => (Input => Peer_States);

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
       and then HS.Kind = Handshake.State_Empty
       and then (if Is_Success (Result) then Is_Peer_Established (Peer));

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

   --  Snapshot the previous keypair for a peer into KP.
   --  Used for previous-key fallback during rekey transitions:
   --  in-flight packets encrypted under the old key can still be
   --  decrypted via the Previous slot until the next rekey overwrites it.
   procedure Get_Previous (Peer : Peer_Index; KP : out Keypair)
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

   --  Record that we sent a DATA packet (not keepalive) to this peer.
   --  Used by unresponsive peer detection (§6.5): if we sent data but
   --  got no reply in New_Handshake_Time_Ms (15 s), initiate a rekey.
   procedure Mark_Data_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
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

   --  Check the counter against the peer's previous keypair replay filter.
   --  Used for previous-key fallback: when a transport packet decrypts
   --  successfully with the Previous key, its counter must be validated
   --  against the Previous slot's replay filter (separate counter space).
   procedure Validate_And_Update_Replay_Previous
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

   ---------------------------------------------------------------------------
   --  Persistent keepalive configuration
   ---------------------------------------------------------------------------

   --  Set the persistent keepalive interval for a peer.
   --  Interval_S = 0 disables persistent keepalive.
   --  Per WireGuard §6.5: recommended range is 1..65535 seconds;
   --  typical value is 25 seconds.
   procedure Set_Persistent_Keepalive
     (Peer : Peer_Index; Interval_S : Unsigned_64)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
     Post => Session_Ready;

   --  Clear the Last_Handshake timestamp for a peer.
   --  Called by the Zero_All_Keys handler at 540 s to prevent
   --  the zeroing action from firing repeatedly.  After this call,
   --  Tick will no longer see a stale Last_Handshake for this peer.
   procedure Clear_Handshake_Timestamp (Peer : Peer_Index)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  => Session_Ready,
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
      Last_Data_Sent : Timer.Clock.Timestamp := Timer.Clock.Never;
      Last_Received  : Timer.Clock.Timestamp := Timer.Clock.Never;
      Last_Handshake : Timer.Clock.Timestamp := Timer.Clock.Never;

      --  Rekey timestamps (timer path)
      Rekey_Start     : Timer.Clock.Timestamp := Timer.Clock.Never;
      Rekey_Last_Sent : Timer.Clock.Timestamp := Timer.Clock.Never;

      Active       : Boolean    := False;
      Mode         : Peer_Mode  := Inactive;

      --  True when we initiated the current session's handshake.
      --  Per WireGuard §5.4: only the initiator may do time-based
      --  opportunistic rekeying, to prevent the "thundering herd"
      --  problem where both peers try to rekey simultaneously.
      Is_Initiator : Boolean    := False;

      --  Persistent keepalive interval in milliseconds (0 = disabled).
      --  Per WireGuard §6.5: if configured, the peer unconditionally
      --  sends an empty transport packet every N seconds to keep
      --  NAT mappings and stateful firewalls open.  Stored as ms so
      --  it can be compared directly against the ms-resolution
      --  monotonic clock; the public Set_Persistent_Keepalive setter
      --  takes seconds and converts.
      Persistent_Keepalive_Ms : Unsigned_64 := 0;

      --  Jitter added to rekey retry interval (0..2000 ms).
      --  Per §6.1: prevents lock-step retransmissions between peers.
      --  Generated from Fill_Random in Set_Rekey_Flag on each retry.
      Rekey_Jitter_Ms : Unsigned_64 := 0;

      --  Transition flag: persistent-keepalive deadline has elapsed
      --  since the last outbound packet.  Set lazily by
      --  Refresh_Time_Flags in Session.Timers (called at the entry
      --  of Tick_All / On_Peer_Timer_Due) and cleared by Mark_Sent
      --  and Set_Persistent_Keepalive.  Tick reads this flag instead
      --  of computing Now - Last_Sent >= Persistent_Keepalive_Ms.
      --  Step 6b.1 of the timer-driven migration; remaining elapsed-
      --  time conditions in Tick will be converted in follow-up
      --  commits.
      Persistent_Keepalive_Due : Boolean := False;
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

   function Is_Peer_Established (Peer : Peer_Index) return Boolean
   is (Peers (Peer).Mode = Established);

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
