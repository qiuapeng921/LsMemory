
UNICODE_STRING usDeivceName = RTL_CONSTANT_STRING(L"\\Device\\LsMemory");
UNICODE_STRING usSymbolicName = RTL_CONSTANT_STRING(L"\\??\\LsMemory");

#define IoctlIoMemoryCard               CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 卡密验证
#define IoctlIoMemoryReadWriteMod		CTL_CODE(FILE_DEVICE_UNKNOWN, 802, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 内存_读写模式
#define IoctlIoMemoryModuleAddress      CTL_CODE(FILE_DEVICE_UNKNOWN, 803, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 内存_取模块地址
#define IoctlIoMemoryRead               CTL_CODE(FILE_DEVICE_UNKNOWN, 804, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 内存_读取
#define IoctlIoMemoryWrite				CTL_CODE(FILE_DEVICE_UNKNOWN, 805, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 内存_写入
#define IoctlIoMemoryAlloc              CTL_CODE(FILE_DEVICE_UNKNOWN, 806, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 内存_申请/释放
#define IoctlIoMemoryHiddenProcess      CTL_CODE(FILE_DEVICE_UNKNOWN, 807, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 隐藏进程
#define IoctlIoMemoryProtectProcess     CTL_CODE(FILE_DEVICE_UNKNOWN, 808, METHOD_BUFFERED, FILE_ANY_ACCESS)	// 保护进程