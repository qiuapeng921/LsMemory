UNICODE_STRING usDeivceName = RTL_CONSTANT_STRING(L"\\Device\\LsMemory");
UNICODE_STRING usSymbolicName = RTL_CONSTANT_STRING(L"\\??\\LsMemory");

#define IOCTL_GET_SECTION_ADDRESS	    CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS)	
#define IOCTL_READ_MEMORY               CTL_CODE(FILE_DEVICE_UNKNOWN, 802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY              CTL_CODE(FILE_DEVICE_UNKNOWN, 803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOCATE_MEMORY           CTL_CODE(FILE_DEVICE_UNKNOWN, 804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_MEMORY               CTL_CODE(FILE_DEVICE_UNKNOWN, 805, METHOD_BUFFERED, FILE_ANY_ACCESS)

