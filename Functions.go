package main

import "syscall"


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


func ResumeThread(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("ResumeThread").Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


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