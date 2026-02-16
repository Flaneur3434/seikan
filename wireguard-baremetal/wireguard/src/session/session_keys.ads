with Handshake;
with Replay;
with Crypto.AEAD;
with Utils.Result;
with Timer.Clock;
with Interfaces; use Interfaces;

use type Handshake.Handshake_State_Kind;

package Session_Keys
  with SPARK_Mode => On,
  Abstract_State => (KP_State)
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

   type Keypair is record
      Send_Key       : Session_Key := [others => 0];
      Receive_Key    : Session_Key := [others => 0];
      Sender_Index   : Unsigned_32 := 0;
      Receiver_Index : Unsigned_32 := 0;
      Send_Counter   : Unsigned_64 := 0;
      Replay_Filter  : Replay.Filter;
      Created_At     : Timer.Clock.Timestamp := Timer.Clock.Never;
      ID             : Keypair_ID := 0;
      Valid          : Boolean := False;
   end record;

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
     Pre    => not Result'Constrained,
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

end Session_Keys;
