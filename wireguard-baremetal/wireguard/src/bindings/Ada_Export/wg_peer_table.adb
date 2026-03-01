--  WG_Peer_Table — C FFI Implementation

with Peer_Table;
with Session;
with Crypto.KX;
with Ada.Unchecked_Conversion;
with System;

package body WG_Peer_Table is

   --------------------------------------------------------------------------
   --  Public key configuration
   --------------------------------------------------------------------------

   procedure C_Set_Public_Key
     (Peer : Interfaces.C.unsigned;
      Key  : access Interfaces.Unsigned_8)
   is
      type Key_Arr is array (0 .. Crypto.KX.Public_Key_Bytes - 1)
        of aliased Interfaces.Unsigned_8
        with Convention => C;
      type Key_Arr_Ptr is access all Key_Arr with Convention => C;

      function To_Key is new Ada.Unchecked_Conversion
        (System.Address, Key_Arr_Ptr);

      Ada_Key : Crypto.KX.Public_Key := [others => 0];
      Arr     : Key_Arr_Ptr;
   begin
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;

      if Key /= null then
         Arr := To_Key (Key.all'Address);
         for I in Ada_Key'Range loop
            Ada_Key (I) := Arr (I);
         end loop;
      end if;

      Peer_Table.Set_Public_Key (Session.Peer_Index (Peer), Ada_Key);
   end C_Set_Public_Key;

   function C_Lookup_By_Key
     (Key : access Interfaces.Unsigned_8)
      return Interfaces.C.unsigned
   is
      type Key_Arr is array (0 .. Crypto.KX.Public_Key_Bytes - 1)
        of aliased Interfaces.Unsigned_8
        with Convention => C;
      type Key_Arr_Ptr is access all Key_Arr with Convention => C;

      function To_Key is new Ada.Unchecked_Conversion
        (System.Address, Key_Arr_Ptr);

      use Peer_Table.Lookup_Result;
      Ada_Key : Crypto.KX.Public_Key := [others => 0];
      Arr     : Key_Arr_Ptr;
   begin
      if Key /= null then
         Arr := To_Key (Key.all'Address);
         for I in Ada_Key'Range loop
            Ada_Key (I) := Arr (I);
         end loop;
      end if;

      declare
         R : constant Peer_Table.Lookup_Result.Result :=
           Peer_Table.Lookup_By_Key (Ada_Key);
      begin
         if R.Kind = Is_Ok then
            return Interfaces.C.unsigned (R.Ok);
         else
            return 0;
         end if;
      end;
   end C_Lookup_By_Key;

   --------------------------------------------------------------------------
   --  AllowedIPs configuration
   --------------------------------------------------------------------------

   procedure C_Set_Allowed_IPs
     (Peer  : Interfaces.C.unsigned;
      IPs   : access C_IP_Prefix;
      Count : Interfaces.C.unsigned)
   is
      use type Interfaces.C.unsigned;

      Ada_IPs : Peer_Table.Allowed_IP_Array := [others => (0, 0)];
      N       : Natural;

      --  Overlay the C pointer as an unchecked array for indexing.
      type C_Prefix_Arr is
        array (Interfaces.C.unsigned range 0 .. Interfaces.C.unsigned'Last)
          of aliased C_IP_Prefix
        with Convention => C;
      type C_Prefix_Arr_Ptr is access all C_Prefix_Arr
        with Convention => C;

      function To_Arr is new Ada.Unchecked_Conversion
        (Source => System.Address,
         Target => C_Prefix_Arr_Ptr);

      Arr : C_Prefix_Arr_Ptr;
   begin
      --  Bounds check: peer index
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;

      --  Clamp count
      if Count > Interfaces.C.unsigned (Peer_Table.Max_Allowed_IPs) then
         return;
      end if;

      N := Natural (Count);

      if N > 0 and then IPs /= null then
         Arr := To_Arr (IPs.all'Address);
         for I in 0 .. Interfaces.C.unsigned (N) - 1 loop
            if Arr (I).Prefix_Len <= 32 then
               Ada_IPs (Natural (I) + 1) :=
                 (Addr       => Arr (I).Addr,
                  Prefix_Len => Natural (Arr (I).Prefix_Len));
            end if;
         end loop;
      end if;

      Peer_Table.Set_Allowed_IPs
        (Peer  => Session.Peer_Index (Peer),
         IPs   => Ada_IPs,
         Count => N);
   end C_Set_Allowed_IPs;

   --------------------------------------------------------------------------
   --  TX routing
   --------------------------------------------------------------------------

   function C_Lookup_By_IP
     (Dest_IP : Interfaces.Unsigned_32)
      return Interfaces.C.unsigned
   is
      use Peer_Table.Lookup_Result;
      R : constant Peer_Table.Lookup_Result.Result :=
        Peer_Table.Lookup_By_IP (Dest_IP);
   begin
      if R.Kind = Is_Ok then
         return Interfaces.C.unsigned (R.Ok);
      else
         return 0;
      end if;
   end C_Lookup_By_IP;

   --------------------------------------------------------------------------
   --  RX source filter
   --------------------------------------------------------------------------

   function C_Check_Source
     (Peer   : Interfaces.C.unsigned;
      Src_IP : Interfaces.Unsigned_32)
      return Interfaces.C.unsigned_char
   is
   begin
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return 0;
      end if;

      declare
         use Peer_Table.Source_Result;
         R : constant Peer_Table.Source_Result.Result :=
           Peer_Table.Check_Source (Session.Peer_Index (Peer), Src_IP);
      begin
         if R.Kind = Is_Ok then
            return 1;
         else
            return 0;
         end if;
      end;
   end C_Check_Source;

   --------------------------------------------------------------------------
   --  Endpoint management
   --------------------------------------------------------------------------

   procedure C_Update_Endpoint
     (Peer : Interfaces.C.unsigned;
      Addr : Interfaces.Unsigned_32;
      Port : Interfaces.Unsigned_16)
   is
   begin
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;

      Peer_Table.Update_Endpoint
        (Session.Peer_Index (Peer), Addr, Port);
   end C_Update_Endpoint;

   function C_Get_Endpoint
     (Peer     : Interfaces.C.unsigned;
      Out_Addr : access Interfaces.Unsigned_32;
      Out_Port : access Interfaces.Unsigned_16)
      return Interfaces.C.unsigned_char
   is
      EP : Peer_Table.Endpoint;
   begin
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return 0;
      end if;

      Peer_Table.Get_Endpoint (Session.Peer_Index (Peer), EP);

      if not EP.Valid then
         return 0;
      end if;

      Out_Addr.all := EP.Addr;
      Out_Port.all := EP.Port;
      return 1;
   end C_Get_Endpoint;

end WG_Peer_Table;
