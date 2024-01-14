package bof

/*

 credits: COFFLoader (by Kevin Haubris/@kev169)
 ported to golang. For sektor 7 advanced malware course @rez0h
 original work: https://github.com/latortuga71/GOCoffLoader
*/

// #include "beacon_compatibility.h"
import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"
	"unsafe"

	"github.com/parzel/GoBofRunner/helper"
)

var output string

//export GoBeaconOutput
func GoBeaconOutput(data *C.char) {
	output += C.GoString(data)
}

var functionMapping = map[string]uintptr{
	"BeaconDataParse":    uintptr(unsafe.Pointer(C.BeaconDataParse)),
	"BeaconDataInt":      uintptr(unsafe.Pointer(C.BeaconDataInt)),
	"BeaconDataShort":    uintptr(unsafe.Pointer(C.BeaconDataShort)),
	"BeaconDataLength":   uintptr(unsafe.Pointer(C.BeaconDataLength)),
	"BeaconDataExtract":  uintptr(unsafe.Pointer(C.BeaconDataExtract)),
	"BeaconFormatAlloc":  uintptr(unsafe.Pointer(C.BeaconFormatAlloc)),
	"BeaconFormatReset":  uintptr(unsafe.Pointer(C.BeaconFormatReset)),
	"BeaconFormatFree":   uintptr(unsafe.Pointer(C.BeaconFormatFree)),
	"BeaconFormatAppend": uintptr(unsafe.Pointer(C.BeaconFormatAppend)),
	//	"BeaconFormatPrintf":           uintptr(unsafe.Pointer(C.BeaconFormatPrintf)),
	"BeaconFormatToString":         uintptr(unsafe.Pointer(C.BeaconFormatToString)),
	"BeaconFormatInt":              uintptr(unsafe.Pointer(C.BeaconFormatInt)),
	"BeaconPrintf":                 uintptr(C.GetBeaconPrintf()),
	"BeaconOutput":                 uintptr(C.GetBeaconOutput()),
	"BeaconUseToken":               uintptr(unsafe.Pointer(C.BeaconUseToken)),
	"BeaconRevertToken":            uintptr(unsafe.Pointer(C.BeaconRevertToken)),
	"BeaconIsAdmin":                uintptr(unsafe.Pointer(C.BeaconIsAdmin)),
	"BeaconGetSpawnTo":             uintptr(unsafe.Pointer(C.BeaconGetSpawnTo)),
	"BeaconSpawnTemporaryProcess":  uintptr(unsafe.Pointer(C.BeaconSpawnTemporaryProcess)),
	"BeaconInjectProcess":          uintptr(unsafe.Pointer(C.BeaconInjectProcess)),
	"BeaconInjectTemporaryProcess": uintptr(unsafe.Pointer(C.BeaconInjectTemporaryProcess)),
	"BeaconCleanupProcess":         uintptr(unsafe.Pointer(C.BeaconCleanupProcess)),
	"BeaconGetOutputData":          uintptr(unsafe.Pointer(C.BeaconGetOutputData)),
}

const debugging bool = false

func DebugPrint(args ...interface{}) {
	if !debugging {
		return
	}
	arg1 := args[0]
	arg1Str := "DEBUG " + arg1.(string)
	fmt.Printf(arg1Str, args[1:]...)
}

func ParseCoff(coff []byte, beaconData []byte) string {
	output = ""
	// parse header
	coffHdrPtr := (*helper.COFF_FILE_HEADER)(unsafe.Pointer(&coff[0]))
	headerOffset := unsafe.Sizeof(helper.COFF_FILE_HEADER{})
	sectionSize := unsafe.Sizeof(helper.COFF_SECTION{})
	totalSectionSize := sectionSize * uintptr(coffHdrPtr.NumberOfSections)
	var coffRelocPtr *helper.COFF_RELOCATION
	var coffSymbolPtr *helper.COFF_SYMBOL
	var baseAddressOfMemory uintptr
	var err error
	DebugPrint("[+] Machine Header: 0x%x\n", coffHdrPtr.Machine)
	DebugPrint("[+] Machine Header: 0x%x\n", coffHdrPtr.Machine)
	DebugPrint("[+] Number Of Sections: %d\n", coffHdrPtr.NumberOfSections)
	DebugPrint("[+] TimeDate Stamp 0x%x\n", coffHdrPtr.TimeDateStamp)
	DebugPrint("[+] Pointer To Symbol Table: 0x%x\n", coffHdrPtr.PointerToSymbolTable)
	DebugPrint("[+] Number Of Symbols %d\n", coffHdrPtr.NumberOfSymbols)
	DebugPrint("[+] Size Of Optional Header %d\n", coffHdrPtr.SizeOfOptionalHeader)
	DebugPrint("[+] Characteristcs 0x%x\n", coffHdrPtr.Characteristics)
	// allocate memory for all sections here
	baseAddressOfMemory, err = VirtualAlloc(0, uint32(totalSectionSize), helper.MEM_COMMIT|helper.MEM_RESERVE, helper.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}

	memorySections := (*helper.COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	// parse sections
	for x := 0; x < int(coffHdrPtr.NumberOfSections); x++ {
		coffSectionPtr := (*helper.COFF_SECTION)(unsafe.Pointer(&coff[headerOffset+sectionSize*uintptr(x)]))
		if coffSectionPtr.SizeOfRawData < 0 {
			// no data to save in this section.
		}
		// debug
		DebugPrint("[+] Section %d\n", x)
		DebugPrint("[+] Name %s\n", coffSectionPtr.Name)
		DebugPrint("[+] VirtualSize 0x%x\n", coffSectionPtr.VirtualSize)
		DebugPrint("[+] VirtualAddress 0x%x\n", coffSectionPtr.VirtualAddress)
		DebugPrint("[+] Size of raw data %d\n", coffSectionPtr.SizeOfRawData)
		DebugPrint("[+] Pointer to raw data 0x%x\n", coffSectionPtr.PointerToRawData)
		DebugPrint("[+] Pointer to relocations 0x%x\n", coffSectionPtr.PointerToRelocations)
		DebugPrint("[+] Pointer to line numbers 0x%x\n", coffSectionPtr.PointerToLineNumbers)
		// copy section to memory
		memorySections.Counter = uint32(x)
		copy(memorySections.Name[:], coffSectionPtr.Name[:])
		memorySections.SizeOfRawData = coffSectionPtr.SizeOfRawData
		memorySections.PointerToRawData = coffSectionPtr.PointerToRawData
		memorySections.PointerToRelocations = coffSectionPtr.PointerToRelocations
		memorySections.NumberOfRelocations = coffSectionPtr.NumberOfRelocations
		memorySections.Characteristics = coffSectionPtr.Characteristics
		memorySections.InMemorySize = memorySections.SizeOfRawData + (0x1000 - memorySections.SizeOfRawData%0x1000)
		// check if needs to be executable
		if memorySections.Characteristics&helper.IMAGE_SCN_CNT_CODE != 0 {
			memorySections.InMemoryAddress, err = VirtualAlloc(0, memorySections.InMemorySize, helper.MEM_COMMIT|helper.MEM_TOP_DOWN, helper.PAGE_READWRITE)
			if err != nil {
				log.Fatal(err)
			}
		}
		memorySections.InMemoryAddress, err = VirtualAlloc(0, memorySections.InMemorySize, helper.MEM_COMMIT|helper.MEM_TOP_DOWN, helper.PAGE_EXECUTE_READWRITE)
		if err != nil {
			log.Fatal(err)
		}
		var wrote uint32
		success, err := WriteProcessMemory(helper.HSelf, memorySections.InMemoryAddress, uintptr(unsafe.Pointer(&coff[0]))+uintptr(coffSectionPtr.PointerToRawData), coffSectionPtr.SizeOfRawData, &wrote)
		if !success {
			log.Fatal(err)
		}
		if memorySections.NumberOfRelocations != 0 {
			// print relocation table
			for i := 0; i < int(memorySections.NumberOfRelocations); i++ {
				coffRelocPtr = (*helper.COFF_RELOCATION)(unsafe.Pointer(&coff[memorySections.PointerToRelocations+uint32(10*i)]))
				DebugPrint("Reloc %d\n", i)
				DebugPrint("VADdress 0x%.9x\n", coffRelocPtr.VirtualAddress)
				DebugPrint("SymTab ins %5.d\n", coffRelocPtr.SymbolTableIndex)
				DebugPrint("Type 0x%.5x\n", coffRelocPtr.Type)
			}
		}
		// increase memory sections pointer
		memorySections = (*helper.COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + unsafe.Sizeof(helper.COFF_MEM_SECTION{})))
	}
	/// allocate memory for symbol table
	numSymbols := coffHdrPtr.NumberOfSymbols
	symAddrSize := uint32(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{}))
	memSymbolsBaseAddress, err := VirtualAlloc(0, symAddrSize*numSymbols, helper.MEM_COMMIT|helper.MEM_RESERVE, helper.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}
	memSymbols := (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	// got start of symbol table
	coffSymbolPtr = (*helper.COFF_SYMBOL)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable]))
	coffStringsPtr := (*byte)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable+numSymbols*18]))
	// print symbols table
	for i := 0; i < int(numSymbols); i++ {
		DebugPrint("%d\n", i)
		DebugPrint("0x%.12x\n", coffSymbolPtr.Value)
		DebugPrint("0x%.9x\n", coffSymbolPtr.SectionNumber)
		DebugPrint("%6.4d\n", coffSymbolPtr.Type)
		DebugPrint("%.13d\n", coffSymbolPtr.StorageClass)
		if coffSymbolPtr.SectionNumber == 0 && coffSymbolPtr.StorageClass == 0 {
			copy(memSymbols.Name[:], "__UNDEFINED")
		} else {
			if coffSymbolPtr.ShortName[3] != 0 || coffSymbolPtr.ShortName[0] != 0 {
				n := make([]byte, 10)
				copy(n, coffSymbolPtr.ShortName[0:8])
				copy(memSymbols.Name[:], n)
			} else {
				strLoc := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(coffStringsPtr)) + uintptr(uint32(binary.LittleEndian.Uint32(coffSymbolPtr.ShortName[4:])))))
				// copy string to our memory.
				var counter = 0
				for {
					if *strLoc == 0 {
						break
					}
					memSymbols.Name[counter] = *strLoc
					counter++
					strLoc = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(strLoc)) + 1))
				}
			}
		}
		// save data in internal symbols table that we allocated
		memSymbols.Counter = uint32(i)
		memSymbols.SectionNumber = coffSymbolPtr.SectionNumber
		memSymbols.Value = coffSymbolPtr.Value
		memSymbols.StorageClass = coffSymbolPtr.StorageClass
		memSymbols.InMemoryAddress = 0
		// increase both pointers
		coffSymbolPtr = (*helper.COFF_SYMBOL)(unsafe.Pointer(uintptr(unsafe.Pointer(coffSymbolPtr)) + 18))
		memSymbols = (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})))

	}
	got, err := VirtualAlloc(0, 2048, helper.MEM_COMMIT|helper.MEM_RESERVE|helper.MEM_TOP_DOWN, helper.PAGE_READWRITE)
	if err != nil {
		log.Fatal(err)
	}

	// resolve symbols
	entryPoint := ResolveSymbols(got, memSymbolsBaseAddress, numSymbols, baseAddressOfMemory)
	DebugPrint("resolved symbols %x\n", entryPoint)
	for i := 0; i < int(numSymbols); i++ {
		memSymbols = (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbolsBaseAddress)) + unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(i)))
		DebugPrint("%4d ", i)
		DebugPrint("VALUE 0x%x ", memSymbols.Value)
		DebugPrint("SECTION 0x%x ", memSymbols.SectionNumber)
		DebugPrint("STORAGE CLASS 0x%x ", memSymbols.StorageClass)
		DebugPrint("InMemAddress 0x%x ", memSymbols.InMemoryAddress)
		DebugPrint("GOT Address 0x%x ", memSymbols.GOTAddress)
		DebugPrint("NAME %s\n", memSymbols.Name)
	}
	//time.Sleep(time.Hour * 1)
	//fix relocations.
	memorySections = (*helper.COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	for i := 0; i < int(coffHdrPtr.NumberOfSections); i++ {
		memorySectionPtr := (*helper.COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr(unsafe.Sizeof(helper.COFF_MEM_SECTION{})*uintptr(i))))
		if memorySectionPtr.NumberOfRelocations == 0 {
			continue
		}
		for j := 0; j < int(memorySectionPtr.NumberOfRelocations); j++ {
			coffRelocPtr = (*helper.COFF_RELOCATION)(unsafe.Pointer(&coff[memorySectionPtr.PointerToRelocations+uint32(10*j)]))
			switch coffRelocPtr.Type {
			case 0x1:
				// untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				offset64 := uint64(where)
				what64 := (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress + offset64
				ok, err := WriteProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&what64)), 8, nil)
				if !ok {
					log.Fatal(err)
				}
				break
			case 0x3:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := ReadProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4)
				what3232 = uint32(what32)
				ok, err = WriteProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				DebugPrint("0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				break
			case 0x4:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := ReadProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				if (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress != 0 {
					DebugPrint("GOT addres\n")
					DebugPrint("where 0x%x\n", memSymbolsBaseAddress)
					DebugPrint("where 0x%x\n", memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))
					//time.Sleep(time.Hour * 1)
					what32 := (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress - uint64(where+4)
					what3232 = uint32(what32)
				} else {
					what32 := uint64(offset32Num) + (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress - uint64(where+4)
					what3232 = uint32(what32)
				}
				DebugPrint("where 0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				ok, err = WriteProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				break
			case 0x8:
				//untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := ReadProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4+4)
				what3232 = uint32(what32)
				ok, err = WriteProcessMemory(helper.HSelf, where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					log.Fatal(err)
				}
				DebugPrint("0x%x\n", where)
				DebugPrint("offset32 %d\n", binary.LittleEndian.Uint32(offset32[:]))
				DebugPrint("what32 0x%x\n", what3232)
				break
			default:
				DebugPrint("Reloc is not supported!\n")
				log.Fatal(fmt.Errorf("Relocation Type Not Supported"))
			}
		}
	}
	DebugPrint("Relocations done\n")
	C.RunBof(unsafe.Pointer(entryPoint), unsafe.Pointer(&beaconData[0]), C.uint64_t(len(beaconData)))
	return output
}

func trimstr(old string) string {
	var new = ""
	for _, c := range old {
		if c == 0 {
			break
		}
		new += string(c)
	}
	return new
}

func ResolveSymbols(GOT uintptr, memSymbolsBaseAddress uintptr, nSymbols uint32, memSectionsBaseAddress uintptr) uintptr {
	GOTIdx := 0
	memSymbols := (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	memorySections := (*helper.COFF_MEM_SECTION)(unsafe.Pointer(memSectionsBaseAddress))
	var symbol [256]byte
	var strSymbol string
	var dllName string
	var funcName string
	var entryPoint uintptr
	section := 0
	DebugPrint("%d symbols\n", nSymbols)
	for i := 0; i < int(nSymbols); i++ {
		copy(symbol[:], memSymbols.Name[:])
		strSymbol = trimstr(string(symbol[:]))
		DebugPrint("SYMBOL -> %s\n", strSymbol)
		memSymbols.GOTAddress = 0
		if memSymbols.SectionNumber > 0xff {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "__UNDEFINED") {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "imp_") {
			var funcAddress uintptr
			var lib syscall.Handle
			// here we attach the beacon functions
			if strings.Contains(strSymbol, "Beacon") {
				DebugPrint("We found a beacon function\n")
				funcName = strings.Split(strSymbol, "__imp_")[1]
				funcAddress = functionMapping[funcName]
				DebugPrint("0x%x\n", uint64(funcAddress))
			} else {
				//if not beacon
				if !strings.Contains(strSymbol, "$") {
					dllName = "kernel32"
					funcName = strings.Split(strSymbol, "__imp_")[1]
				} else {
					dllName = strings.Split(strSymbol, "__imp_")[1]
					dllName = strings.Split(dllName, "$")[0]
					funcName = strings.Split(strSymbol, "$")[1]
				}
				DebugPrint("DLL %s\nFUNC %s\n", dllName, funcName)
				var err error
				lib, err = syscall.LoadLibrary(dllName + ".dll")
				if err != nil {
					log.Fatal(err)
				}
				DebugPrint("Library Handle 0x%x\n", lib)
				if lib != 0 {
					funcAddress, err = syscall.GetProcAddress(lib, funcName)
					if funcAddress == 0 {
						log.Fatal(err)
					}
				}
			}
			if funcAddress == 0 {
				log.Fatal(fmt.Errorf("failed to get proc address"))
			}
			DebugPrint("0x%x\n", uint64(funcAddress))
			memSymbols.InMemoryAddress = uint64(funcAddress)
			DebugPrint("0x%x\n", memSymbols.InMemoryAddress)
			var wrote uint32
			ok, err := WriteProcessMemory(helper.HSelf, GOT+(uintptr(GOTIdx)*8), uintptr(unsafe.Pointer(&memSymbols.InMemoryAddress)), 8, &wrote)
			if !ok {
				log.Fatal(err, wrote)
			}
			memSymbols.GOTAddress = uint64(GOT + (uintptr(GOTIdx * 8))) //uint64((GOT + (uintptr(GOTIdx) * 8)))
			DebugPrint("0x%x\n", memSymbols.GOTAddress)
			GOTIdx++
		} else {
			section = int(memSymbols.SectionNumber) - 1
			movedPtr := (*helper.COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr((unsafe.Sizeof(helper.COFF_MEM_SECTION{}) * uintptr(section)))))
			memSymbols.InMemoryAddress = uint64(movedPtr.InMemoryAddress + uintptr(memSymbols.Value))
			if strSymbol == "go" {
				DebugPrint("Entry -> 0x%x\n", memSymbols.InMemoryAddress)
				entryPoint = uintptr(memSymbols.InMemoryAddress)
			}
		}
		// move pointer
		memSymbols = (*helper.COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(helper.COFF_SYM_ADDRESS{})))
	}
	return entryPoint
}

func ReadMemUntilNull(start *byte) []byte {
	out := make([]byte, 0)
	var x = 0
	for {
		if *start == 0 {
			break
		}
		out = append(out, *start)
		x++
		start = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(start)) + uintptr(x)))
	}
	return out
}
