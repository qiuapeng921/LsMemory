
UNICODE_STRING usDeivceName = RTL_CONSTANT_STRING(L"\\Device\\LsMemory");
UNICODE_STRING usSymbolicName = RTL_CONSTANT_STRING(L"\\??\\LsMemory");

#define IoctlIoMemoryCard               CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS)	// ������֤
#define IoctlIoMemoryReadWriteMod		CTL_CODE(FILE_DEVICE_UNKNOWN, 802, METHOD_BUFFERED, FILE_ANY_ACCESS)	// �ڴ�_��дģʽ
#define IoctlIoMemoryModuleAddress      CTL_CODE(FILE_DEVICE_UNKNOWN, 803, METHOD_BUFFERED, FILE_ANY_ACCESS)	// �ڴ�_ȡģ���ַ
#define IoctlIoMemoryRead               CTL_CODE(FILE_DEVICE_UNKNOWN, 804, METHOD_BUFFERED, FILE_ANY_ACCESS)	// �ڴ�_��ȡ
#define IoctlIoMemoryWrite				CTL_CODE(FILE_DEVICE_UNKNOWN, 805, METHOD_BUFFERED, FILE_ANY_ACCESS)	// �ڴ�_д��
#define IoctlIoMemoryAlloc              CTL_CODE(FILE_DEVICE_UNKNOWN, 806, METHOD_BUFFERED, FILE_ANY_ACCESS)	// �ڴ�_����/�ͷ�
#define IoctlIoMemoryHiddenProcess      CTL_CODE(FILE_DEVICE_UNKNOWN, 807, METHOD_BUFFERED, FILE_ANY_ACCESS)	// ���ؽ���
#define IoctlIoMemoryProtectProcess     CTL_CODE(FILE_DEVICE_UNKNOWN, 808, METHOD_BUFFERED, FILE_ANY_ACCESS)	// ��������