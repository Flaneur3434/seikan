--  Session - Implementation

with Replay;

package body Session
  with
    SPARK_Mode    => On,
    Refined_State => (Peer_States => Peers, Mutex_State => Mtx)
is
   use Session_Keys;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref)
   is
   begin
      Threads.Mutex.Init_From_Handle (Mtx, Sem);
      Peers := [others => Null_Peer];
      Session_Keys.Init;
   end Init;

   ---------------------------------------------------------------------------
   --  Lock / Unlock
   ---------------------------------------------------------------------------

   procedure Lock is
   begin
      Threads.Mutex.Lock (Mtx);
   end Lock;

   procedure Unlock is
   begin
      Threads.Mutex.Unlock (Mtx);
   end Unlock;

   ---------------------------------------------------------------------------
   --  Activate_Next
   ---------------------------------------------------------------------------

   procedure Activate_Next (Peer : Peer_Index) is
   begin
      --  Rotate keys: Next → Current → Previous, clear Next.
      --  Order matters: save Current before overwriting.
      Peers (Peer).Previous        := Peers (Peer).Current;
      Peers (Peer).Current         := Peers (Peer).Next;
      Peers (Peer).Next            := Null_Keypair;
      Peers (Peer).Last_Handshake  := Peers (Peer).Current.Created_At;
      Peers (Peer).Rekey_Start     := Timer.Clock.Never;
      Peers (Peer).Rekey_Last_Sent := Timer.Clock.Never;
      Peers (Peer).Active          := True;
      Peers (Peer).Mode            := Established;
   end Activate_Next;

   ---------------------------------------------------------------------------
   --  Derive_And_Activate (atomic compound operation)
   ---------------------------------------------------------------------------

   function Mode_Of (P : Peer_Index) return Peer_Mode
      is (Peers (P).Mode);

   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with
     Refined_Post =>
       Is_Mtx_Initialized
       and then not Is_Mtx_Locked
       and then All_Peers_Valid
       and then HS.Kind = Handshake.State_Empty
       and then (if Result = Success then Mode_Of (Peer) = Established)
   is
      Derive_Result : Keypair_Result.Result;
   begin
      Lock;

      Session_Keys.Derive_Keypair (HS, Now, Derive_Result);
      case Derive_Result.Kind is
         when Keypair_Result.Is_Ok  =>
            --  Place in the Next slot directly (overwrite, no wipe needed)
            Peers (Peer).Next := Derive_Result.Ok;
            Peers (Peer).Next.Valid := True;

            --  Activate_Next does the whole-record rotation
            --  including Mode := Established and rekey clearing
            Activate_Next (Peer);
            Result := Success;

         when Keypair_Result.Is_Err =>
            Result := Error_Failed;
      end case;

      Unlock;
   end Derive_And_Activate;

   ---------------------------------------------------------------------------
   --  Get_Current
   ---------------------------------------------------------------------------

   procedure Get_Current (Peer : Peer_Index; KP : out Keypair) is
   begin
      Lock;
      KP := Peers (Peer).Current;
      Unlock;
   end Get_Current;

   ---------------------------------------------------------------------------
   --  Timestamp updates
   ---------------------------------------------------------------------------

   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Sent := Now;
      Unlock;
   end Mark_Sent;

   procedure Mark_Received (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Received := Now;
      Unlock;
   end Mark_Received;

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64)
   is
   begin
      Lock;
      Counter := Peers (Peer).Current.Send_Counter;
      Peers (Peer).Current.Send_Counter := Counter + 1;
      Unlock;
   end Increment_Send_Counter;

   ---------------------------------------------------------------------------
   --  Timer-driven session management
   ---------------------------------------------------------------------------

   procedure Expire_Session (Peer : Peer_Index)
   with
     Refined_Post =>
       Is_Mtx_Initialized
       and then not Is_Mtx_Locked
       and then All_Peers_Valid
       and then not Peers (Peer).Current.Valid
       and then not Peers (Peer).Previous.Valid
       and then not Peers (Peer).Next.Valid
   is
   begin
      Lock;

      Peers (Peer) := Null_Peer;

      Unlock;
   end Expire_Session;

   procedure Set_Rekey_Flag
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;

      case Peers (Peer).Mode is
         when Established =>
            --  Transition Established → Rekeying.
            --  Valid_Peer(Established) guarantees Active and Current.Valid,
            --  which Valid_Peer(Rekeying) also requires.
            Peers (Peer).Mode            := Rekeying;
            Peers (Peer).Rekey_Start     := Now;
            Peers (Peer).Rekey_Last_Sent := Now;

         when Rekeying =>
            --  Already rekeying — only update retry timestamp.
            Peers (Peer).Rekey_Last_Sent := Now;

         when Inactive =>
            --  No session to rekey — no-op.
            null;
      end case;

      Unlock;
   end Set_Rekey_Flag;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean)
   is
   begin
      Lock;

      Replay.Validate_Counter
        (F        => Peers (Peer).Current.Replay_Filter,
         Counter  => Counter,
         Limit    => Reject_After_Messages,
         Accepted => Accepted);

      Unlock;
   end Validate_And_Update_Replay;

end Session;
