package bof

import (
	"unsafe"

	"github.com/f1zm0/acheron"
	"github.com/parzel/GoBofRunner/helper"
)

// var (
// 	pModKernel32        = syscall.NewLazyDLL("kernel32.dll")
// 	pVirtualAlloc       = pModKernel32.NewProc("VirtualAlloc")
// 	pWriteProcessMemory = pModKernel32.NewProc("WriteProcessMemory")
// 	pReadProcessMemory  = pModKernel32.NewProc("ReadProcessMemory")
// )

var Ach, err = acheron.New()

func WriteProcessMemory(hProcess uintptr, lpAddresss uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesWritten *uint32) (bool, error) {
	// writeMem, _, err := pWriteProcessMemory.Call(
	// 	hProcess,
	// 	lpAddresss,
	// 	lpBuffer,
	// 	uintptr(nSize),
	// 	uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	// if writeMem == 0 {
	// 	return false, err
	// }
	// return true, nil

	// as we only writing to our local process, we can just perform a memcpy and save us this API call
	for i := uintptr(0); i < uintptr(nSize); i++ {
		*(*byte)(unsafe.Pointer(lpAddresss + i)) = *(*byte)(unsafe.Pointer(lpBuffer + i))
	}
	return true, nil
}

func VirtualAlloc(lpAddress uintptr, dwSize uint32, allocationType uintptr, flProtect uintptr) (uintptr, error) {
	// lpBaseAddress, _, err := pVirtualAlloc.Call(
	// 	lpAddress,
	// 	uintptr(dwSize),
	// 	uintptr(allocationType),
	// 	uintptr(flProtect))
	// if lpBaseAddress == 0 {
	// 	return 0, err
	// }
	// return lpBaseAddress, nil

	//here we use indirect syscalls via acheron
	var baseAddressOfMemory uintptr
	var regionSize = uintptr(dwSize)
	if _, err := Ach.Syscall(
		Ach.HashString("NtAllocateVirtualMemory"),
		helper.HSelf,
		uintptr(unsafe.Pointer(&baseAddressOfMemory)),
		uintptr(unsafe.Pointer(nil)),
		uintptr(unsafe.Pointer(&regionSize)),
		allocationType,
		flProtect,
	); err != nil {
		return 0, err
	}
	return baseAddressOfMemory, nil
}

func ReadProcessMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesRead *uint32) (bool, error) {
	// ok, _, err := pReadProcessMemory.Call(
	// 	hProcess,
	// 	lpBaseAddress,
	// 	lpBuffer,
	// 	uintptr(nSize),
	// 	uintptr(unsafe.Pointer(lpNumberOfBytesRead)))
	// if ok == 0 {
	// 	return false, err
	// }

	// as we only reading from our local process, we can just perform a memcpy and save us this API call
	for i := uintptr(0); i < uintptr(nSize); i++ {
		*(*byte)(unsafe.Pointer(lpBuffer + i)) = *(*byte)(unsafe.Pointer(lpBaseAddress + i))
	}
	return true, nil
}
