--  Session - WireGuard Transport Session Management
--
--  Owns all transport session state for up to Max_Peers concurrent peers.
--  Each peer has three session slots:
--
--    Current  — Active session for sending and receiving
--    Previous — Retired session, kept alive to decrypt in-flight packets
--               that were encrypted under the old key before the peer
--               completed the rekey
--    Next     — Being negotiated via in-progress handshake
--
--  Three slots are necessary because rekey is not atomic: after we
--  rotate (Next → Current), the peer may still have packets in the
--  network encrypted with the old Current.  Keeping Previous lets us
--  decrypt those stragglers without dropping them.
--
--  When a handshake completes:
--    Previous := Current, Current := Next, Next := Null_Keypair
--
--  Session lookup by receiver_index is O(1) — receiver_index values
--  are assigned as direct array indices (1..Max_Peers).
--
--  Thread safety:
--    All session state is protected by a per-table mutex.
--    The timer task locks during its scan; the WG task locks during
--    encrypt/decrypt.  The mutex is a binary semaphore created in C
--    and passed via Init.
--
--  Design principle: "Ada is the brain, C is the hands"
--    Ada owns all session state and timer logic.
--    C handles I/O, queues, and FreeRTOS task management.

with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.AEAD;
with Handshake;
with Replay;
with Timer.Clock;
with Threads.Mutex;

use type Handshake.Handshake_State_Kind;

package Session
  with SPARK_Mode => On
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
   Rekey_After_Time   : constant Unsigned_64 := 120;
   Reject_After_Time  : constant Unsigned_64 := 180;
   Rekey_Attempt_Time : constant Unsigned_64 := 90;
   Rekey_Timeout      : constant Unsigned_64 := 5;
   Keepalive_Timeout  : constant Unsigned_64 := 10;

   ---------------------------------------------------------------------------
   --  Peer Index — Direct-mapped array index (1..Max_Peers)
   ---------------------------------------------------------------------------

   subtype Peer_Index is Positive range 1 .. Max_Peers;

   ---------------------------------------------------------------------------
   --  Keypair — One direction's transport keys + counters
   --
   --  Limited private: callers get exactly one snapshot at a time
   --  via Get_Current.  No copies, no aliases — thread safe by
   --  construction.  Internal slot rotation uses the non-limited
   --  full type visible in the private section.
   ---------------------------------------------------------------------------

   subtype Session_Key is Crypto.AEAD.Key_Buffer;

   type Keypair_ID is new Unsigned_32;
   Null_Keypair_ID : constant Keypair_ID := 0;

   type Keypair is limited private;

   ---------------------------------------------------------------------------
   --  Keypair accessors (read-only)
   ---------------------------------------------------------------------------

   function Is_Valid (KP : Keypair) return Boolean;
   function Send_Key (KP : Keypair) return Session_Key;
   function Receive_Key (KP : Keypair) return Session_Key;
   function Receiver_Index (KP : Keypair) return Unsigned_32;

   ---------------------------------------------------------------------------
   --  Peer_State — limited private, visible only to child packages
   ---------------------------------------------------------------------------

   type Peer_State is limited private;

   ---------------------------------------------------------------------------
   --  Ghost state — bridges private Mtx into public contracts
   ---------------------------------------------------------------------------

   function Is_Mtx_Initialized return Boolean
   with Ghost;
   --  True after Init has been called.  Wraps Threads.Mutex.Is_Initialized
   --  on the private Mtx so public contracts can reference it.

   function Is_Mtx_Locked return Boolean
   with Ghost;
   --  True while the session mutex is held.  Wraps Threads.Mutex.Is_Locked
   --  on the private Mtx so public contracts can reference lock state.

   ---------------------------------------------------------------------------
   --  Initialization
   ---------------------------------------------------------------------------

   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref)
   with Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Initialize the session table and mutex.
   --  Must be called once at startup before any session operations.

   ---------------------------------------------------------------------------
   --  Session lifecycle
   --
   --  All operations below are thread-safe: they acquire the session
   --  mutex internally.  Callers must NOT hold the mutex.
   --
   --  Ghost contracts guarantee lock discipline:
   --    Pre:  mutex initialized and NOT held (caller must not hold it)
   --    Post: mutex initialized and NOT held (always released on exit)
   ---------------------------------------------------------------------------

   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked
                and then HS.Kind = Handshake.State_Empty;
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

   ---------------------------------------------------------------------------
   --  Session lookup
   ---------------------------------------------------------------------------

   procedure Get_Current (Peer : Peer_Index; KP : out Keypair)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Snapshot the current keypair for a peer into KP.
   --  KP is the sole snapshot — limited type prevents copies.

   ---------------------------------------------------------------------------
   --  Send/Receive timestamp updates
   ---------------------------------------------------------------------------

   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Record that we sent a packet to this peer.

   procedure Mark_Received (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Record that we received a valid packet from this peer.

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Read and increment the current keypair's send counter.
   --  Returns the counter value BEFORE increment (used as nonce).

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Check the counter against the peer's current keypair replay filter.
   --  If valid, updates the filter to include this counter value.

   ---------------------------------------------------------------------------
   --  Timer-driven session management
   --
   --  Called by the WG task in response to timer events.
   --  Thread-safe: acquire the session mutex internally.
   ---------------------------------------------------------------------------

   procedure Expire_Session (Peer : Peer_Index)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Wipe all three keypair slots for a peer.
   --  Called on Session_Expired and Rekey_Timed_Out.

   procedure Set_Rekey_Flag
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with Pre  => Is_Mtx_Initialized and then not Is_Mtx_Locked,
        Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;
   --  Mark rekey in progress before sending initiation.

   ---------------------------------------------------------------------------
   --  Private — visible to child packages (Session.Timers)
   --
   --  State lives here (not in the body) so Session.Timers can read
   --  the Peers array directly during Tick_All without re-locking.
   ---------------------------------------------------------------------------

private

   ---------------------------------------------------------------------------
   --  Full type definitions — non-limited so internal slot rotation works.
   --  Externally these are limited private: no copies outside this package.
   --  Child packages (Session.Timers) see these full definitions.
   ---------------------------------------------------------------------------

   type Keypair is record
      Send_Key       : Session_Key;
      Receive_Key    : Session_Key;
      Sender_Index   : Unsigned_32;
      Receiver_Index : Unsigned_32;
      Send_Counter   : Unsigned_64;
      Replay_Filter  : Replay.Filter;
      Created_At     : Timer.Clock.Timestamp;
      ID             : Keypair_ID;
      Valid          : Boolean;
   end record;

   Null_Keypair : constant Keypair :=
     (Send_Key       => (others => 0),
      Receive_Key    => (others => 0),
      Sender_Index   => 0,
      Receiver_Index => 0,
      Send_Counter   => 0,
      Replay_Filter  => Replay.Empty_Filter,
      Created_At     => Timer.Clock.Never,
      ID             => Null_Keypair_ID,
      Valid          => False);

   type Peer_State is record
      --  Three session slots
      Current  : Keypair;
      Previous : Keypair;
      Next     : Keypair;

      --  Timer state (checked by Session.Timers.Tick)
      Last_Sent           : Timer.Clock.Timestamp;  --  Last outbound packet
      Last_Received       : Timer.Clock.Timestamp;  --  Last inbound packet
      Last_Handshake      : Timer.Clock.Timestamp;  --  When current was born
      Rekey_Attempted     : Boolean;                --  Rekey in progress?
      Rekey_Attempt_Start : Timer.Clock.Timestamp;  --  When rekey began

      --  Is this peer slot in use?
      Active : Boolean;
   end record;

   Null_Peer : constant Peer_State :=
     (Current             => Null_Keypair,
      Previous            => Null_Keypair,
      Next                => Null_Keypair,
      Last_Sent           => Timer.Clock.Never,
      Last_Received       => Timer.Clock.Never,
      Last_Handshake      => Timer.Clock.Never,
      Rekey_Attempted     => False,
      Rekey_Attempt_Start => Timer.Clock.Never,
      Active              => False);

   Peers      : array (Peer_Index) of Peer_State := (others => Null_Peer);
   Mtx        : Threads.Mutex.Mutex_Handle;
   Next_KP_ID : Keypair_ID := 1;

   --  Ghost bridge completions — here (not in the body) so child
   --  packages (Session.Timers) can see through the abstraction.
   function Is_Mtx_Initialized return Boolean is
     (Threads.Mutex.Is_Initialized (Mtx));
   function Is_Mtx_Locked return Boolean is
     (Threads.Mutex.Is_Locked (Mtx));

   procedure Lock
   with
     Global => (In_Out => Mtx),
     Pre    => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx),
     Post   => Is_Mtx_Initialized and then Threads.Mutex.Is_Locked (Mtx);

   procedure Unlock
   with
     Global => (In_Out => Mtx),
     Pre    => Is_Mtx_Initialized and then Threads.Mutex.Is_Locked (Mtx),
     Post   => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx);

   --  Lock-free internal helpers — caller must hold the mutex.
   --  Visible in private so Session.Timers can potentially reuse.

   procedure Derive_Keypair
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with Global => (In_Out => (Peers, Next_KP_ID)),
        Post   => HS.Kind = Handshake.State_Empty;
   --  Derive transport keys from completed handshake chaining key.
   --  Places new keypair in the peer's Next slot.
   --  Wipes handshake ephemeral material — ALWAYS, even on failure.
   --  Forward secrecy: Post guarantees no handshake material survives.
   --  Caller holds lock.

   procedure Activate_Next (Peer : Peer_Index)
   with Global => (In_Out => Peers),
        Post   => not Peers (Peer).Next.Valid;
   --  Promote Next → Current, Current → Previous, Previous → wiped.
   --  Post guarantees: Next slot is always cleared after rotation.
   --  If Next was invalid on entry, this is a no-op (still not Valid).
   --  Caller holds lock.

end Session;
