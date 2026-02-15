with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.AEAD;
with Handshake;
with Replay;
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

   ---------------------------------------------------------------------------
   --  Initialization
   ---------------------------------------------------------------------------

   --  Initialize the session table and mutex.
   --  Must be called once at startup before any session operations.
   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref)
   with Post => Is_Mtx_Initialized and then not Is_Mtx_Locked;

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
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   =>
       Is_Mtx_Initialized
       and then not Is_Mtx_Locked
       and then HS.Kind = Handshake.State_Empty;

   ---------------------------------------------------------------------------
   --  Session lookup
   ---------------------------------------------------------------------------

   --  Snapshot the current keypair for a peer into KP.
   --  KP is the sole snapshot — limited type prevents copies.
   procedure Get_Current (Peer : Peer_Index; KP : out Session_Keys.Keypair)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   ---------------------------------------------------------------------------
   --  Send/Receive timestamp updates
   ---------------------------------------------------------------------------

   --  Record that we sent a packet to this peer.
   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (Output => Peer_States, In_Out => Mutex_State),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   --  Record that we received a valid packet from this peer.
   procedure Mark_Received (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (Output => Peer_States, In_Out => Mutex_State),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   --  Read and increment the current keypair's send counter.
   --  Returns the counter value BEFORE increment (used as nonce).
   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   --  Check the counter against the peer's current keypair replay filter.
   --  If valid, updates the filter to include this counter value.
   procedure Validate_And_Update_Replay
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

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
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;

   --  Mark rekey in progress before sending initiation.
   procedure Set_Rekey_Flag (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre    => Is_Mtx_Initialized and then not Is_Mtx_Locked,
     Post   => Is_Mtx_Initialized and then not Is_Mtx_Locked;


private

   type Peer_Mode is (Inactive, Established, Rekeying);

   type Rekey_Substate is (Waiting_For_Response, Retry_Ready);

   type Rekey_State is record
      Start_At  : Timer.Clock.Timestamp;  --  When rekey began
      Last_Sent : Timer.Clock.Timestamp;  --  When last initiation sent
      Phase     : Rekey_Substate;
   end record;

   type Peer_State is record
      --  Three session slots
      Current  : Session_Keys.Keypair;
      Previous : Session_Keys.Keypair;
      Next     : Session_Keys.Keypair;

      --  Timestamps used by timer state machine (checked by Session.Timers.Tick)
      Last_Sent      : Timer.Clock.Timestamp;  --  Last outbound packet
      Last_Received  : Timer.Clock.Timestamp;  --  Last inbound packet
      Last_Handshake : Timer.Clock.Timestamp;  --  When current was born
      Rekey          : Rekey_State;

      Active : Boolean; --  Is this peer slot in use?
      Mode   : Peer_Mode;
   end record
   with
     --  Check structural invariant
     Type_Invariant =>
       (case Mode is
          when Inactive    => not Active or not Current.Valid,
          when Established =>
            Active
            and then Current.Valid
            and then Rekey.Start_At = Timer.Clock.Never
            and then Rekey.Last_Sent = Timer.Clock.Never,
          when Rekeying    =>
            Active
            and then Current.Valid
            and then Rekey.Start_At /= Timer.Clock.Never
            and then Rekey.Last_Sent /= Timer.Clock.Never);

   Null_Peer : constant Peer_State :=
     (Current        => Session_Keys.Null_Keypair,
      Previous       => Session_Keys.Null_Keypair,
      Next           => Session_Keys.Null_Keypair,
      Last_Sent      => Timer.Clock.Never,
      Last_Received  => Timer.Clock.Never,
      Last_Handshake => Timer.Clock.Never,
      Rekey          =>
        (Start_At  => Timer.Clock.Never,
         Last_Sent => Timer.Clock.Never,
         Phase     => Waiting_For_Response),
      Active         => False,
      Mode           => Inactive);

   Peers : array (Peer_Index) of Peer_State := (others => Null_Peer)
   with Part_Of => Peer_States;
   Mtx   : Threads.Mutex.Mutex_Handle
   with Part_Of => Mutex_State;

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
   with Global => (In_Out => Peers), Post => not Peers (Peer).Next.Valid;

end Session;
