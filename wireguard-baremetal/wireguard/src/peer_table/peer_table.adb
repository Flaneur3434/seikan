--  Peer_Table — Implementation

package body Peer_Table
  with SPARK_Mode => On
is

   --------------------------------------------------------------------------
   --  Internal state
   --------------------------------------------------------------------------

   type Peer_Entry is record
      Pub_Key  : Crypto.KX.Public_Key := [others => 0];
      Allowed  : Allowed_IP_Array := [others => (0, 0)];
      AIP_Cnt  : Natural range 0 .. Max_Allowed_IPs := 0;
      EP       : Endpoint := (Addr => 0, Port => 0, Valid => False);
   end record;

   Peers : array (Session.Peer_Index) of Peer_Entry :=
     [others => <>];

   --------------------------------------------------------------------------
   --  Prefix matching helper
   --------------------------------------------------------------------------

   --  Build a bitmask for a given prefix length.
   --  E.g. Prefix_Len=24 → 16#FFFFFF00#, Prefix_Len=0 → 0.
   function Prefix_Mask (Len : Natural) return Unsigned_32
   with
     Pre => Len <= 32
   is
   begin
      if Len = 0 then
         return 0;
      elsif Len = 32 then
         return 16#FFFF_FFFF#;
      else
         --  Shift left then fill from MSB.
         --  For network byte order IPs, the mask is applied directly.
         return Shift_Left (16#FFFF_FFFF#,
                            32 - Len);
      end if;
   end Prefix_Mask;

   function Matches
     (IP : Unsigned_32; Prefix : IP_Prefix) return Boolean
   is
      Mask : constant Unsigned_32 := Prefix_Mask (Prefix.Prefix_Len);
   begin
      return (IP and Mask) = (Prefix.Addr and Mask);
   end Matches;

   --------------------------------------------------------------------------
   --  Set_Public_Key
   --------------------------------------------------------------------------

   procedure Set_Public_Key
     (Peer : Session.Peer_Index;
      Key  : Crypto.KX.Public_Key)
   is
   begin
      Peers (Peer).Pub_Key := Key;
   end Set_Public_Key;

   --------------------------------------------------------------------------
   --  Set_Allowed_IPs
   --------------------------------------------------------------------------

   procedure Set_Allowed_IPs
     (Peer  : Session.Peer_Index;
      IPs   : Allowed_IP_Array;
      Count : AIP_Count)
   is
   begin
      Peers (Peer).Allowed := IPs;
      Peers (Peer).AIP_Cnt := Count;
   end Set_Allowed_IPs;

   --------------------------------------------------------------------------
   --  Lookup_By_IP — longest prefix match across all peers
   --------------------------------------------------------------------------

   function Lookup_By_IP
     (Dest_IP : Unsigned_32) return Lookup_Result.Result
   is
      Best_Len  : Natural := 0;
      Best_Peer : Session.Peer_Index := Session.Peer_Index'First;
      Hit       : Boolean := False;
   begin
      for P in Session.Peer_Index loop
         for I in 1 .. Peers (P).AIP_Cnt loop
            declare
               Pfx : IP_Prefix renames Peers (P).Allowed (I);
            begin
               if Matches (Dest_IP, Pfx) then
                  if not Hit or else Pfx.Prefix_Len > Best_Len then
                     Best_Peer := P;
                     Best_Len  := Pfx.Prefix_Len;
                     Hit       := True;
                  end if;
               end if;
            end;
         end loop;
      end loop;

      if Hit then
         return Lookup_Result.Ok (Best_Peer);
      else
         return Lookup_Result.Err (No_Match);
      end if;
   end Lookup_By_IP;

   --------------------------------------------------------------------------
   --  Lookup_By_Key — find peer by static public key
   --------------------------------------------------------------------------

   function Lookup_By_Key
     (Key : Crypto.KX.Public_Key) return Lookup_Result.Result
   is
      use type Crypto.KX.Public_Key;
      Zero : constant Crypto.KX.Public_Key := [others => 0];
   begin
      for P in Session.Peer_Index loop
         if Peers (P).Pub_Key /= Zero
           and then Peers (P).Pub_Key = Key
         then
            return Lookup_Result.Ok (P);
         end if;
      end loop;
      return Lookup_Result.Err (No_Match);
   end Lookup_By_Key;

   --------------------------------------------------------------------------
   --  Check_Source — RX AllowedIPs source filter
   --------------------------------------------------------------------------

   function Check_Source
     (Peer   : Session.Peer_Index;
      Src_IP : Unsigned_32) return Source_Result.Result
   is
   begin
      for I in 1 .. Peers (Peer).AIP_Cnt loop
         if Matches (Src_IP, Peers (Peer).Allowed (I)) then
            return Source_Result.Ok (Peer);
         end if;
      end loop;
      return Source_Result.Err (Rejected);
   end Check_Source;

   --------------------------------------------------------------------------
   --  Endpoint management
   --------------------------------------------------------------------------

   procedure Update_Endpoint
     (Peer : Session.Peer_Index;
      Addr : Unsigned_32;
      Port : Unsigned_16)
   is
   begin
      Peers (Peer).EP := (Addr  => Addr,
                          Port  => Port,
                          Valid => True);
   end Update_Endpoint;

   procedure Get_Endpoint
     (Peer  : Session.Peer_Index;
      EP    : out Endpoint)
   is
   begin
      EP := Peers (Peer).EP;
   end Get_Endpoint;

end Peer_Table;
