#include"WriteMemory.h"

NTSTATUS NTAPI NtProtectVirtualMemory(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection) {

	typedef NTSTATUS(NTAPI* ZwProtectVirtualMemoryProc)(
		IN HANDLE               ProcessHandle,
		IN OUT PVOID* BaseAddress,
		IN OUT PULONG           NumberOfBytesToProtect,
		IN ULONG                NewAccessProtection,
		OUT PULONG              OldAccessProtection);

	static ZwProtectVirtualMemoryProc MyZwProtectVirtualMemory = NULL;
	if (!MyZwProtectVirtualMemory)
	{
		UNICODE_STRING usFunctionName = { 0 };
		RtlInitUnicodeString(&usFunctionName, L"ZwIsProcessInJob");
		PUCHAR puFunctionAddr = (PUCHAR)MmGetSystemRoutineAddress(&usFunctionName);
		if (puFunctionAddr)
		{
			puFunctionAddr += 20;
			for (size_t i = 0; i < 50; i++)
			{	//特征码搜索
				if (puFunctionAddr[i] == 0x48 && puFunctionAddr[i + 1] == 0x8b && puFunctionAddr[i + 2] == 0xc4) {
					MyZwProtectVirtualMemory = (ZwProtectVirtualMemoryProc)(puFunctionAddr + i);
					break;
				}
			}
		}
	}
	if (MyZwProtectVirtualMemory)
	{
		return MyZwProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
	}

}


NTSTATUS WriteMemory(HANDLE hProcessID, PVOID pBaseAddress, PVOID pBuffer, SIZE_T szBufferSize)
{
	if ((ULONG64)pBaseAddress >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize >= MmHighestUserAddress || (ULONG64)pBaseAddress + szBufferSize < (ULONG64)pBaseAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	if (pBuffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_3;
	}
	PEPROCESS pEprocess;
	KAPC_STATE kApc = { 0 };
	NTSTATUS ntStatus = PsLookupProcessByProcessId(hProcessID, &pEprocess);
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	if (PsGetProcessExitStatus(pEprocess) != STATUS_PENDING)
	{
		ObDereferenceObject(pEprocess);
		return STATUS_INVALID_PARAMETER_1;
	}

	SIZE_T retNum = 0;
	//直接先写一次
	ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
	if (NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(pEprocess);
		return ntStatus;

	}
	//没有写成功
	PEPROCESS pCurrentEprocess = IoGetCurrentProcess();
	KeStackAttachProcess(pEprocess, &kApc);
	PVOID pvAddr = pBaseAddress;
	SIZE_T szSize = szBufferSize;
	ULONG ulAttr = 0;
	ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, PAGE_EXECUTE_READWRITE, &ulAttr);
	if (NT_SUCCESS(ntStatus))
	{
		SIZE_T retNum = 0;
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		NtProtectVirtualMemory(NtCurrentProcess(), &pvAddr, &szSize, ulAttr, &ulAttr);
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);
	if (!NT_SUCCESS(ntStatus))
	{
		//关中断
		_disable();
		//读取CR0
		ULONG64 ulRegCr0 = __readcr0();
		__writecr0(ulRegCr0 & (~0x10000));//关保护
		ntStatus = MmCopyVirtualMemory(IoGetCurrentProcess(), pBuffer, pEprocess, pBaseAddress, szBufferSize, UserMode, &retNum);
		__writecr0(ulRegCr0);
		_enable();
	}
	return ntStatus;
}


NTSTATUS WriteProcessMemory(HANDLE pid, PVOID address, PVOID bufferaddress, SIZE_T BufferSize)
{

	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pMemory = ExAllocatePool(NonPagedPool, BufferSize);
	RtlZeroMemory(&pMemory, BufferSize);
	process = IoGetCurrentProcess();
	status = PsLookupProcessByProcessId(pid, &process);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error 0x1\n");
		return FALSE;
	}

	KAPC_STATE stack = { 0 };
	KeStackAttachProcess(process, &stack);
	PMDL mdl = NULL;

	mdl = MmCreateMdl(NULL, address, 4);
	if (mdl == NULL)
	{
		DbgPrint("Error 0x1\n");
		return FALSE;
	}


	MmBuildMdlForNonPagedPool(mdl);

	__try
	{
		pMemory = MmMapLockedPages(mdl, KernelMode);
	}
	__except (1)
	{

		DbgPrint("Memory mapping failed.\n");

		IoFreeMdl(mdl);
		ObDereferenceObject(process);
		KeUnstackDetachProcess(&stack);
		return FALSE;
	}

	RtlCopyMemory(pMemory, &bufferaddress, BufferSize);
	DbgPrint("进程ID:%d 地址:%x 写入数据:%d", pid, address, *(PVOID*)pMemory);
	IoFreeMdl(mdl);
	MmUnmapLockedPages(pMemory, mdl);
	ObDereferenceObject(process);
	KeUnstackDetachProcess(&stack);

	return TRUE;
}


NTSTATUS KernelWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID Targetaddress, SIZE_T Size) {
	SIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		Targetaddress, Size, KernelMode, &Bytes)))
	{
		return STATUS_SUCCESS;
	}
	return STATUS_ACCESS_DENIED;
}