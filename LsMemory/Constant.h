
UNICODE_STRING usDeivceName = RTL_CONSTANT_STRING(L"\\Device\\LsMemory");
UNICODE_STRING usSymbolicName = RTL_CONSTANT_STRING(L"\\??\\LsMemory");

#define IoctlCard						CTL_CODE(FILE_DEVICE_UNKNOWN, 801, METHOD_BUFFERED, FILE_ANY_ACCESS) // ������֤
#define IoctlReadWriteMod				CTL_CODE(FILE_DEVICE_UNKNOWN, 802, METHOD_BUFFERED, FILE_ANY_ACCESS) // ��дģʽ
#define IoctlModuleAddress				CTL_CODE(FILE_DEVICE_UNKNOWN, 803, METHOD_BUFFERED, FILE_ANY_ACCESS) // ȡģ���ַ
#define IoctlModuleFuncAddress			CTL_CODE(FILE_DEVICE_UNKNOWN, 804, METHOD_BUFFERED, FILE_ANY_ACCESS) // ȡģ�麯����ַ
#define IoctlRead						CTL_CODE(FILE_DEVICE_UNKNOWN, 805, METHOD_BUFFERED, FILE_ANY_ACCESS) // ��ȡ����
#define IoctlWrite						CTL_CODE(FILE_DEVICE_UNKNOWN, 806, METHOD_BUFFERED, FILE_ANY_ACCESS) // д������
#define IoctlAlloc						CTL_CODE(FILE_DEVICE_UNKNOWN, 807, METHOD_BUFFERED, FILE_ANY_ACCESS) // �����ڴ�
#define IoctlFree						CTL_CODE(FILE_DEVICE_UNKNOWN, 808, METHOD_BUFFERED, FILE_ANY_ACCESS) // �ͷ��ڴ�
#define IoctlHiddenProcessOn			CTL_CODE(FILE_DEVICE_UNKNOWN, 809, METHOD_BUFFERED, FILE_ANY_ACCESS) // ���ؽ���-����
#define IoctlHiddenProcessOff			CTL_CODE(FILE_DEVICE_UNKNOWN, 810, METHOD_BUFFERED, FILE_ANY_ACCESS) // ���ؽ���-�ر�
#define IoctlProtectProcessOn			CTL_CODE(FILE_DEVICE_UNKNOWN, 811, METHOD_BUFFERED, FILE_ANY_ACCESS) // ��������-����
#define IoctlProtectProcessOff			CTL_CODE(FILE_DEVICE_UNKNOWN, 812, METHOD_BUFFERED, FILE_ANY_ACCESS) // ��������-�ر�

// ����ṹ
typedef struct _DataStruct
{
	ULONG	ProcessPid;
	PVOID	TargetAddress;
	ULONG	Length;
	PVOID	Buffer;
} DataStruct, * PDataStruct;