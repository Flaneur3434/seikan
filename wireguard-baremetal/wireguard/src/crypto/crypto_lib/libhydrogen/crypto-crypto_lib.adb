--  Crypto library initialization and wrapper implementations for libhydrogen

with Ada.Unchecked_Conversion;
with Crypto.Blake2_Ref;

package body Crypto.Crypto_Lib
  with SPARK_Mode => Off
is
   use type System.Address;

   --  libhydrogen context string for VeriGuard operations
   WG_Context : constant String (1 .. 8) := "VeriGuar";

   --  hydro_kx_keypair layout: pk[32] + sk[32] = 64 bytes
   type KX_Keypair is record
      PK : aliased Interfaces.C.char_array (0 .. 31);
      SK : aliased Interfaces.C.char_array (0 .. 31);
   end record
     with Convention => C, Size => 64 * 8;

   ---------------------
   --  Raw libhydrogen imports
   ---------------------

   procedure Hydro_KX_Keygen (Keypair : System.Address)
   with Import, Convention => C, External_Name => "hydro_kx_keygen";

   procedure Hydro_KX_Keygen_Deterministic
     (Keypair : System.Address; Seed : System.Address)
   with Import, Convention => C, External_Name => "hydro_kx_keygen_deterministic";

   function Hydro_Secretbox_Encrypt
     (Ciphertext_Out : System.Address;
      Message_In     : System.Address;
      Message_Len    : size_t;
      Msg_ID         : Interfaces.C.unsigned_long;
      Ctx            : System.Address;
      Key            : System.Address) return int
   with Import, Convention => C, External_Name => "hydro_secretbox_encrypt";

   function Hydro_Secretbox_Decrypt
     (Message_Out    : System.Address;
      Ciphertext_In  : System.Address;
      Ciphertext_Len : size_t;
      Msg_ID         : Interfaces.C.unsigned_long;
      Ctx            : System.Address;
      Key            : System.Address) return int
   with Import, Convention => C, External_Name => "hydro_secretbox_decrypt";

   function Hydro_Equal
     (A : System.Address; B : System.Address; Length : size_t)
      return Interfaces.C.C_bool
   with Import, Convention => C, External_Name => "hydro_equal";

   ---------------------
   --  Generate_Keypair
   ---------------------
   function Generate_Keypair
     (Public_Key_Out : System.Address; Secret_Key_Out : System.Address)
      return int
   is
      Keypair : KX_Keypair;
   begin
      Hydro_KX_Keygen (Keypair'Address);

      declare
         type Byte_Array is array (0 .. 31) of Interfaces.C.unsigned_char
           with Convention => C;
         type Byte_Array_Ptr is access all Byte_Array;

         function To_Ptr is new Ada.Unchecked_Conversion
           (System.Address, Byte_Array_Ptr);

         PK_Out : constant Byte_Array_Ptr := To_Ptr (Public_Key_Out);
         SK_Out : constant Byte_Array_Ptr := To_Ptr (Secret_Key_Out);
      begin
         for I in 0 .. 31 loop
            PK_Out (I) := Interfaces.C.unsigned_char'Val
              (Interfaces.C.char'Pos (Keypair.PK (size_t (I))));
            SK_Out (I) := Interfaces.C.unsigned_char'Val
              (Interfaces.C.char'Pos (Keypair.SK (size_t (I))));
         end loop;
      end;

      return 0;
   end Generate_Keypair;

   ---------------------
   --  Derive_Public_Key
   ---------------------
   function Derive_Public_Key
     (Public_Key_Out : System.Address; Secret_Key_In : System.Address)
      return int
   is
      Keypair : KX_Keypair;
   begin
      Hydro_KX_Keygen_Deterministic (Keypair'Address, Secret_Key_In);

      declare
         type Byte_Array is array (0 .. 31) of Interfaces.C.unsigned_char
           with Convention => C;
         type Byte_Array_Ptr is access all Byte_Array;

         function To_Ptr is new Ada.Unchecked_Conversion
           (System.Address, Byte_Array_Ptr);

         PK_Out : constant Byte_Array_Ptr := To_Ptr (Public_Key_Out);
      begin
         for I in 0 .. 31 loop
            PK_Out (I) := Interfaces.C.unsigned_char'Val
              (Interfaces.C.char'Pos (Keypair.PK (size_t (I))));
         end loop;
      end;

      return 0;
   end Derive_Public_Key;

   ---------------------
   --  DH_Key_Exchange
   ---------------------
   function DH_Key_Exchange
     (Shared_Secret_Out   : System.Address;
      My_Secret_Key_In    : System.Address;
      Their_Public_Key_In : System.Address) return int
   is
      type Combined_Keys is array (0 .. 63) of Interfaces.C.unsigned_char
        with Convention => C;

      Combined : Combined_Keys;
      Result   : int;

      type Byte_Array is array (0 .. 31) of Interfaces.C.unsigned_char
        with Convention => C;
      type Byte_Array_Ptr is access all Byte_Array;

      function To_Ptr is new Ada.Unchecked_Conversion
        (System.Address, Byte_Array_Ptr);

      My_SK    : constant Byte_Array_Ptr := To_Ptr (My_Secret_Key_In);
      Their_PK : constant Byte_Array_Ptr := To_Ptr (Their_Public_Key_In);
   begin
      for I in 0 .. 31 loop
         Combined (I)      := My_SK (I);
         Combined (I + 32) := Their_PK (I);
      end loop;

      Result := Crypto.Blake2_Ref.Blake2s
        (Buffer_Out      => Shared_Secret_Out,
         Buffer_Out_Size => 32,
         Buffer_In       => Combined'Address,
         Buffer_In_Size  => 64,
         Key_In          => System.Null_Address,
         Key_In_Size     => 0);

      return Result;
   end DH_Key_Exchange;

   ---------------------
   --  AEAD_Encrypt
   ---------------------
   function AEAD_Encrypt
     (Ciphertext_Out     : System.Address;
      Ciphertext_Len_Out : System.Address;
      Message_In         : System.Address;
      Message_Len        : unsigned_long_long;
      Ad_In              : System.Address;
      Ad_Len             : unsigned_long_long;
      Nsec               : System.Address;
      Nonce_In           : System.Address;
      Key_In             : System.Address) return int
   is
      pragma Unreferenced (Ad_In, Ad_Len, Nsec);

      type Nonce_Array is array (0 .. 11) of Interfaces.C.unsigned_char
        with Convention => C;
      type Nonce_Ptr is access all Nonce_Array;

      function To_Nonce is new Ada.Unchecked_Conversion
        (System.Address, Nonce_Ptr);

      Nonce  : constant Nonce_Ptr := To_Nonce (Nonce_In);
      Msg_ID : Interfaces.C.unsigned_long := 0;

      type ULL_Ptr is access all unsigned_long_long;
      function To_ULL is new Ada.Unchecked_Conversion (System.Address, ULL_Ptr);

      Result : int;
   begin
      for I in 0 .. 7 loop
         Msg_ID := Msg_ID or
           Interfaces.C.unsigned_long (Nonce (I)) * (2 ** (I * 8));
      end loop;

      Result := Hydro_Secretbox_Encrypt
        (Ciphertext_Out => Ciphertext_Out,
         Message_In     => Message_In,
         Message_Len    => size_t (Message_Len),
         Msg_ID         => Msg_ID,
         Ctx            => WG_Context'Address,
         Key            => Key_In);

      if Ciphertext_Len_Out /= System.Null_Address then
         To_ULL (Ciphertext_Len_Out).all := Message_Len + 36;
      end if;

      return Result;
   end AEAD_Encrypt;

   ---------------------
   --  AEAD_Decrypt
   ---------------------
   function AEAD_Decrypt
     (Message_Out     : System.Address;
      Message_Len_Out : System.Address;
      Nsec            : System.Address;
      Ciphertext_In   : System.Address;
      Ciphertext_Len  : unsigned_long_long;
      Ad_In           : System.Address;
      Ad_Len          : unsigned_long_long;
      Nonce_In        : System.Address;
      Key_In          : System.Address) return int
   is
      pragma Unreferenced (Ad_In, Ad_Len, Nsec);

      type Nonce_Array is array (0 .. 11) of Interfaces.C.unsigned_char
        with Convention => C;
      type Nonce_Ptr is access all Nonce_Array;

      function To_Nonce is new Ada.Unchecked_Conversion
        (System.Address, Nonce_Ptr);

      Nonce  : constant Nonce_Ptr := To_Nonce (Nonce_In);
      Msg_ID : Interfaces.C.unsigned_long := 0;

      type ULL_Ptr is access all unsigned_long_long;
      function To_ULL is new Ada.Unchecked_Conversion (System.Address, ULL_Ptr);

      Result : int;
   begin
      for I in 0 .. 7 loop
         Msg_ID := Msg_ID or
           Interfaces.C.unsigned_long (Nonce (I)) * (2 ** (I * 8));
      end loop;

      Result := Hydro_Secretbox_Decrypt
        (Message_Out    => Message_Out,
         Ciphertext_In  => Ciphertext_In,
         Ciphertext_Len => size_t (Ciphertext_Len),
         Msg_ID         => Msg_ID,
         Ctx            => WG_Context'Address,
         Key            => Key_In);

      if Result = 0 and then Message_Len_Out /= System.Null_Address then
         if Ciphertext_Len >= 36 then
            To_ULL (Message_Len_Out).all := Ciphertext_Len - 36;
         else
            To_ULL (Message_Len_Out).all := 0;
         end if;
      end if;

      return Result;
   end AEAD_Decrypt;

   ---------------------
   --  Constant_Time_Compare
   ---------------------
   function Constant_Time_Compare
     (A : System.Address; B : System.Address; Length : size_t) return int
   is
      Equal : constant Interfaces.C.C_bool := Hydro_Equal (A, B, Length);
   begin
      if Equal then
         return 0;
      else
         return -1;
      end if;
   end Constant_Time_Compare;

   ---------------------
   --  Package Initialization
   ---------------------
   Init_Result : Interfaces.C.int;
begin
   Init_Result := Init;
   pragma Assert (Init_Result = 0, "hydro_init failed");
end Crypto.Crypto_Lib;
