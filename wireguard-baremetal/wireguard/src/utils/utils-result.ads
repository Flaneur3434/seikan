generic
   type T is private;
   type E is private;
package Utils.Result with SPARK_Mode => On is
   type Result_Kind is (Is_Ok, Is_Err);

   type Result (Kind : Result_Kind := Is_Err) is record
      case Kind is
         when Is_Ok  => Ok  : T;
         when Is_Err => Err : E;
      end case;
   end record;

   function Ok (V : T) return Result
   with Global => null,
        Post   => Ok'Result.Kind = Is_Ok and then Ok'Result.Ok = V;

   function Err (V : E) return Result
   with Global => null,
        Post   => Err'Result.Kind = Is_Err and then Err'Result.Err = V;
end Utils.Result;
