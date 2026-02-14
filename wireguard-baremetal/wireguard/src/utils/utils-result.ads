generic
   type T is private;
   type E is private;
package Utils.Result with Spark_Mode => On is
   type Result_Kind is (Is_Ok, Is_Err);

   type Result (K : Result_Kind) is record
      case K is
         when Is_Ok =>
            Ok : T;

         when Is_Err =>
            Err : E;
      end case;
   end record;

   function Ok (V : T) return Result
   with Global => null, Post => Ok'Result.K = Is_Ok;

   function Err (V : E) return Result
   with Global => null, Post => Err'Result.K = Is_Err;
end Utils.Result;
