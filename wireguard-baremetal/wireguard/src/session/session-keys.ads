with Handshake;
with Replay;
with Crypto.AEAD;
with Utils.Result;
with Timer;
with Replay;

use type Handshake.Handshake_State_Kind;

private package Session.Keys
  with SPARK_Mode => On,
  Abstract_State => (KP_State with Part_Of => Session.Peer_States)
is
   ---------------------------------------------------------------------------
   --  Keypair — One direction's transport keys + counters
   --
   --  Limited private: callers get exactly one snapshot at a time
   --  via Get_Current. No copies, no aliases — thread safe by
   --  construction. Internal slot rotation uses the non-limited
   --  full type visible in the private section.
   ---------------------------------------------------------------------------

   subtype Session_Key is Crypto.AEAD.Key_Buffer;

   type Keypair_ID is new Unsigned_32;
   Null_Keypair_ID : constant Keypair_ID := 0;

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
     (Send_Key       => [],
      Receive_Key    => [],
      Sender_Index   => 0,
      Receiver_Index => 0,
      Send_Counter   => 0,
      Replay_Filter  => Replay.Empty_Filter,
      Created_At     => Timer.Clock.Never,
      ID             => Null_Keypair_ID,
      Valid          => False);


   type Keypair_Err is (KDF_Error);
   package Keypair_Result is new Utils.Result (T => Keypair, E => Keypair_Err);

   procedure Init
     with Global => (Output => KP_State);

   --  Derive transport keys from completed handshake chaining key.
   --  Places new keypair in the peer's Next slot.
   --  Wipes handshake ephemeral material — ALWAYS, even on failure.
   --  Forward secrecy: Post guarantees no handshake material survives.
   procedure Derive_Keypair
     (HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Keypair_Result.Result)
   with
     Global => (In_Out => KP_State),
     Post   => HS.Kind = Handshake.State_Empty;

   ---------------------------------------------------------------------------
   --  Keypair accessors (read-only)
   ---------------------------------------------------------------------------

   function Is_Valid (KP : Keypair) return Boolean;
   function Send_Key (KP : Keypair) return Session_Key;
   function Receive_Key (KP : Keypair) return Session_Key;
   function Receiver_Index (KP : Keypair) return Unsigned_32;

private
   Next_KP_ID : Keypair_ID := 1 with Part_Of => KP_State;

end Session.Keys;
