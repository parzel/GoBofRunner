package helper

type ULONGLONG uint64
type DWORD uint32
type LONG uint32
type WORD uint16
type BOOL uint8
type BYTE uint8
type Handle uintptr
type HANDLE uintptr

// special macro that says 'use this thread/process' when provided as a handle.
var HSelf = uintptr(0xffffffffffffffff)

const (
	// Process creation flags.
	CREATE_BREAKAWAY_FROM_JOB        = 0x01000000
	CREATE_DEFAULT_ERROR_MODE        = 0x04000000
	CREATE_NEW_CONSOLE               = 0x00000010
	CREATE_NEW_PROCESS_GROUP         = 0x00000200
	CREATE_NO_WINDOW                 = 0x08000000
	CREATE_PROTECTED_PROCESS         = 0x00040000
	CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000
	CREATE_SEPARATE_WOW_VDM          = 0x00000800
	CREATE_SHARED_WOW_VDM            = 0x00001000
	CREATE_SUSPENDED                 = 0x00000004
	CREATE_UNICODE_ENVIRONMENT       = 0x00000400
	DEBUG_ONLY_THIS_PROCESS          = 0x00000002
	DEBUG_PROCESS                    = 0x00000001
	DETACHED_PROCESS                 = 0x00000008
	EXTENDED_STARTUPINFO_PRESENT     = 0x00080000
	INHERIT_PARENT_AFFINITY          = 0x00010000
	HANDLE_FLAG_INHERIT              = 0x00000001
	STARTF_USESTDHANDLES             = 0x00000100
	STARTF_USESHOWWINDOW             = 0x00000001
	DUPLICATE_CLOSE_SOURCE           = 0x00000001
	DUPLICATE_SAME_ACCESS            = 0x00000002
)

const (
	// winuser.h
	SW_HIDE            = 0
	SW_NORMAL          = 1
	SW_SHOWNORMAL      = 1
	SW_SHOWMINIMIZED   = 2
	SW_SHOWMAXIMIZED   = 3
	SW_MAXIMIZE        = 3
	SW_SHOWNOACTIVATE  = 4
	SW_SHOW            = 5
	SW_MINIMIZE        = 6
	SW_SHOWMINNOACTIVE = 7
	SW_SHOWNA          = 8
	SW_RESTORE         = 9
	SW_SHOWDEFAULT     = 10
	SW_FORCEMINIMIZE   = 11
)

const (
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000

	PAGE_NOACCESS          = 1
	PAGE_READONLY          = 2
	PAGE_READWRITE         = 4
	PAGE_WRITECOPY         = 8
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_NOCACHE           = 0x200

	CFG_CALL_TARGET_VALID = 0x1

	CAL_SMONTHNAME1    = 0x00000015
	ENUM_ALL_CALENDARS = 0xffffffff
	SORT_DEFAULT       = 0x0

	GENERIC_EXECUTE = 0x20000000

	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	IMAGE_FILE_MACHINE_I386          = 0x014c
	IMAGE_FILE_MACHINE_AMD64         = 0x8664
	DLL_PROCESS_ATTACH               = 1
	DLL_THREAD_ATTACH                = 2
	DLL_THREAD_DETACH                = 3
	DLL_PROCESS_DETACH               = 0

	SECTION_QUERY                = 0x0001
	SECTION_MAP_WRITE            = 0x0002
	SECTION_MAP_READ             = 0x0004
	SECTION_MAP_EXECUTE          = 0x0008
	SECTION_EXTEND_SIZE          = 0x0010
	SECTION_MAP_EXECUTE_EXPLICIT = 0x0020
	STANDARD_RIGHTS_REQUIRED     = 0x000F0000
	SEC_IMAGE                    = 0x01000000
	FILE_READ_DATA               = 1

	IMAGE_DIRECTORY_ENTRY_EXPORT         = 0  // Export Directory
	IMAGE_DIRECTORY_ENTRY_IMPORT         = 1  // Import Directory
	IMAGE_DIRECTORY_ENTRY_RESOURCE       = 2  // Resource Directory
	IMAGE_DIRECTORY_ENTRY_EXCEPTION      = 3  // Exception Directory
	IMAGE_DIRECTORY_ENTRY_SECURITY       = 4  // Security Directory
	IMAGE_DIRECTORY_ENTRY_BASERELOC      = 5  // Base Relocation Table
	IMAGE_DIRECTORY_ENTRY_DEBUG          = 6  // Debug Directory
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   = 7  // Architecture Specific Data
	IMAGE_DIRECTORY_ENTRY_GLOBALPTR      = 8  // RVA of GP
	IMAGE_DIRECTORY_ENTRY_TLS            = 9  // TLS Directory
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10 // Load Configuration Directory
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11 // Bound Import Directory in headers
	IMAGE_DIRECTORY_ENTRY_IAT            = 12 // Import Address Table
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13 // Delay Load Import Descriptors
	IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14 // COM Runtime descriptor
	IMAGE_REL_BASED_HIGHLOW              = 3
	IMAGE_REL_BASED_DIR64                = 10
	IMAGE_ORDINAL_FLAG64                 = 0x8000000000000000
	IMAGE_ORDINAL_FLAG32                 = 0x80000000

	// Access rights for process.
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020

	HEAP_ZERO_MEMORY           = 0x00000008
	HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	MEM_DECOMMIT               = 0x00004000
	MEM_RELEASE                = 0x00008000
	MEM_RESET                  = 0x00080000
	MEM_TOP_DOWN               = 0x00100000
	MEM_WRITE_WATCH            = 0x00200000
	MEM_PHYSICAL               = 0x00400000
	MEM_RESET_UNDO             = 0x01000000
	MEM_LARGE_PAGES            = 0x20000000
)

/*
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header

	  WORD   e_magic;                     // Magic number
	  WORD   e_cblp;                      // Bytes on last page of file
	  WORD   e_cp;                        // Pages in file
	  WORD   e_crlc;                      // Relocations
	  WORD   e_cparhdr;                   // Size of header in paragraphs
	  WORD   e_minalloc;                  // Minimum extra paragraphs needed
	  WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	  WORD   e_ss;                        // Initial (relative) SS value
	  WORD   e_sp;                        // Initial SP value
	  WORD   e_csum;                      // Checksum
	  WORD   e_ip;                        // Initial IP value
	  WORD   e_cs;                        // Initial (relative) CS value
	  WORD   e_lfarlc;                    // File address of relocation table
	  WORD   e_ovno;                      // Overlay number
	  WORD   e_res[4];                    // Reserved words
	  WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	  WORD   e_oeminfo;                   // OEM information; e_oemid specific
	  WORD   e_res2[10];                  // Reserved words
	  LONG   e_lfanew;                    // File address of new exe header
	} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type ImageDosHeader struct {
	EMagic    uint16     // Magic number
	ECblp     uint16     // Bytes on last page of file
	ECp       uint16     // Pages in file
	ECrlc     uint16     // Relocations
	ECparhdr  uint16     // Size of header in paragraphs
	EMinalloc uint16     // Minimum extra paragraphs needed
	EMaxalloc uint16     // Maximum extra paragraphs needed
	ESs       uint16     // Initial (relative) SS value
	ESp       uint16     // Initial SP value
	ECsum     uint16     // Checksum
	EIp       uint16     // Initial IP value
	ECs       uint16     // Initial (relative) CS value
	ELfarlc   uint16     // File address of relocation table
	EOvno     uint16     // Overlay number
	ERes      [4]uint16  // Reserved uint16s
	EOemid    uint16     // OEM identifier (for e_oeminfo)
	EOeminfo  uint16     // OEM information; e_oemid specific
	ERes2     [10]uint16 // Reserved uint16s
	ELfanew   uint32     // File address of new exe header
}

/*
	typedef struct _IMAGE_NT_HEADERS {
	    DWORD Signature;
	    IMAGE_FILE_HEADER FileHeader;
	    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
	} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/
type ImageNTHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

type _IMAGE_DATA_DIRECTORY struct {
	VirtualAddress DWORD
	Size           DWORD
}
type IMAGE_DATA_DIRECTORY _IMAGE_DATA_DIRECTORY

type _IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       WORD
	MajorLinkerVersion          BYTE
	MinorLinkerVersion          BYTE
	SizeOfCode                  DWORD
	SizeOfInitializedData       DWORD
	SizeOfUninitializedData     DWORD
	AddressOfEntryPoint         DWORD
	BaseOfCode                  DWORD
	ImageBase                   ULONGLONG
	SectionAlignment            DWORD
	FileAlignment               DWORD
	MajorOperatingSystemVersion WORD
	MinorOperatingSystemVersion WORD
	MajorImageVersion           WORD
	MinorImageVersion           WORD
	MajorSubsystemVersion       WORD
	MinorSubsystemVersion       WORD
	Win32VersionValue           DWORD
	SizeOfImage                 DWORD
	SizeOfHeaders               DWORD
	CheckSum                    DWORD
	Subsystem                   WORD
	DllCharacteristics          WORD
	SizeOfStackReserve          ULONGLONG
	SizeOfStackCommit           ULONGLONG
	SizeOfHeapReserve           ULONGLONG
	SizeOfHeapCommit            ULONGLONG
	LoaderFlags                 DWORD
	NumberOfRvaAndSizes         DWORD
	DataDirectory               [IMAGE_NUMBEROF_DIRECTORY_ENTRIES]IMAGE_DATA_DIRECTORY
}

type IMAGE_OPTIONAL_HEADER64 _IMAGE_OPTIONAL_HEADER64
type IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER64

/*
	typedef struct _IMAGE_FILE_HEADER {
	    WORD    Machine;
	    WORD    NumberOfSections;
	    DWORD   TimeDateStamp;
	    DWORD   PointerToSymbolTable;
	    DWORD   NumberOfSymbols;
	    WORD    SizeOfOptionalHeader;
	    WORD    Characteristics;
	} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

/*
	typedef struct _IMAGE_DATA_DIRECTORY {
	    DWORD   VirtualAddress;
	    DWORD   Size;
	} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
*/
type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

/*
	typedef struct _IMAGE_SECTION_HEADER {
	    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	    union {
	            DWORD   PhysicalAddress;
	            DWORD   VirtualSize;
	    } Misc;
	    DWORD   VirtualAddress;
	    DWORD   SizeOfRawData;
	    DWORD   PointerToRawData;
	    DWORD   PointerToRelocations;
	    DWORD   PointerToLinenumbers;
	    WORD    NumberOfRelocations;
	    WORD    NumberOfLinenumbers;
	    DWORD   Characteristics;
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/
type ImageSectionHeader struct {
	Name                         [8]byte
	PhysicalAddressOrVirtualSize uint32
	VirtualAddress               uint32
	SizeOfRawData                uint32
	PointerToRawData             uint32
	PointerToRelocations         uint32
	PointerToLinenumbers         uint32
	NumberOfRelocations          uint16
	NumberOfLinenumbers          uint16
	Characteristics              uint32
}

type ModuleInfo struct {
	BaseOfDll   uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

/*
typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
  } PEB, *PPEB;
*/

// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.4.0:windows/types_windows.go;l=2444
type PEB struct {
	reserved1              [2]byte
	BeingDebugged          byte
	BitField               byte
	reserved3              uintptr
	ImageBaseAddress       uintptr
	Ldr                    *PEB_LDR_DATA
	ProcessParameters      uintptr
	reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	reserved5              uintptr
	reserved6              uint32
	reserved7              uintptr
	reserved8              uint32
	AtlThunkSListPtr32     uint32
	reserved9              [45]uintptr
	reserved10             [96]byte
	PostProcessInitRoutine uintptr
	reserved11             [128]byte
	reserved12             [1]uintptr
	SessionId              uint32
}

type PEB_LDR_DATA struct {
	reserved1               [8]byte
	reserved2               [3]uintptr
	InMemoryOrderModuleList LIST_ENTRY
}

type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks           LIST_ENTRY
	InMemoryOrderLinks         LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uintptr
	FullDllName                NTUnicodeString
	BaseDllName                NTUnicodeString
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  LIST_ENTRY
	TimeDateStamp              uint64
}

type NTUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// https://github.com/hillu/go-ntdll/blob/ac586c64b9400ae2f79e6bcbd1b932bc21d46e4f/io.go
type IoStatusBlock struct {
	StatusPointer uintptr
	Information   uintptr
}

// ObjectAttributes has been derived from the OBJECT_ATTRIBUTES struct definition.
type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *NTUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type ClientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

const (
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
)

type StartupInfo struct {
	Cb            uint32
	_             *uint16
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
	_             uint16
	_             *byte
	StdInput      Handle
	StdOutput     Handle
	StdErr        Handle
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}

type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

type CFG_CALL_TARGET_INFO struct {
	Offset uintptr
	Flags  uintptr
}

type SYSTEM_PROCESS_INFORMATION struct {
	NextEntryOffset              uint32
	NumberOfThreads              uint32
	WorkingSetPrivateSize        int64
	HardFaultCount               uint32
	NumberOfThreadsHighWatermark uint32
	CycleTime                    uint64
	CreateTime                   int64
	UserTime                     int64
	KernelTime                   int64
	ImageName                    NTUnicodeString
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
	HandleCount                  uint32
	SessionID                    uint32
	UniqueProcessKey             *uint32
	PeakVirtualSize              uintptr
	VirtualSize                  uintptr
	PageFaultCount               uint32
	PeakWorkingSetSize           uintptr
	WorkingSetSize               uintptr
	QuotaPeakPagedPoolUsage      uintptr
	QuotaPagedPoolUsage          uintptr
	QuotaPeakNonPagedPoolUsage   uintptr
	QuotaNonPagedPoolUsage       uintptr
	PagefileUsage                uintptr
	PeakPagefileUsage            uintptr
	PrivatePageCount             uintptr
	ReadOperationCount           int64
	WriteOperationCount          int64
	OtherOperationCount          int64
	ReadTransferCount            int64
	WriteTransferCount           int64
	OtherTransferCount           int64
}

type ProcThreadAttributeList struct{}

type StartupInfoEx struct {
	StartupInfo
	ProcThreadAttributeList *ProcThreadAttributeList
}

type SysProcAttr struct {
	HideWindow                 bool
	CmdLine                    string // used if non-empty, else the windows command line is built by escaping the arguments passed to StartProcess
	CreationFlags              uint32
	Token                      Handle              // if set, runs new process in the security context represented by the token
	ProcessAttributes          *SecurityAttributes // if set, applies these security attributes as the descriptor for the new process
	ThreadAttributes           *SecurityAttributes // if set, applies these security attributes as the descriptor for the main thread of the new process
	NoInheritHandles           bool                // if set, no handles are inherited by the new process, not even the standard handles, contained in ProcAttr.Files, nor the ones contained in AdditionalInheritedHandles
	AdditionalInheritedHandles []Handle            // a list of additional handles, already marked as inheritable, that will be inherited by the new process
	ParentProcess              Handle              // if non-zero, the new process regards the process given by this handle as its parent process, and AdditionalInheritedHandles, if set, should exist in this parent process
}

type SecurityAttributes struct {
	Length             uint32
	SecurityDescriptor uintptr
	InheritHandle      uint32
}

const (
	// do not reorder
	TokenUser = 1 + iota
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
	TokenElevationType
	TokenLinkedToken
	TokenElevation
	TokenHasRestrictions
	TokenAccessInformation
	TokenVirtualizationAllowed
	TokenVirtualizationEnabled
	TokenIntegrityLevel
	TokenUIAccess
	TokenMandatoryPolicy
	TokenLogonSid
	MaxTokenInfoClass
)

// RTL_OSVERSIONINFOEXW
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_osversioninfoexw
// https://github.com/gonutz/w32
type RTL_OSVERSIONINFOEXW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

const (
	MEM_SYMNAME_MAX                  = 100
	IMAGE_SCN_MEM_WRITE              = 0x80000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
)

type COFF_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint16
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// 40 bytes
type COFF_SECTION struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// 10 bytes
type COFF_RELOCATION struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// 18 bytes
type COFF_SYMBOL struct {
	/*
		union {
			char ShortName[8]
			struct {
				uint32_t Zeros;
				uint32_t Offset;
			};
		}
	*/
	ShortName          [8]byte
	Value              uint32
	SectionNumber      uint16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type COFF_MEM_SECTION struct {
	Counter              uint32
	Name                 [10]byte
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	NumberOfRelocations  uint16
	Characteristics      uint32
	InMemoryAddress      uintptr
	InMemorySize         uint32
}

type COFF_SYM_ADDRESS struct {
	Counter         uint32
	Name            [MEM_SYMNAME_MAX]byte
	SectionNumber   uint16
	Value           uint32
	StorageClass    uint8
	InMemoryAddress uint64
	GOTAddress      uint64
}
