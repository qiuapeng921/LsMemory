#include <ntifs.h>

#include "Constant.h"
#include "ReadMemory.h"
#include "WriteMemory.h"
#include "GetModuleBase.h"

// 初始化驱动句柄
NTSTATUS InitDeviceSymbolic(PDRIVER_OBJECT Driver) {
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT pdeojb = { 0 };

	status = IoCreateDevice(Driver, 0, &usDeivceName, FILE_DEVICE_UNKNOWN, 0, 0, &pdeojb);

	if (!NT_SUCCESS(status)) {

		KdPrint(("[LsMemory]:failed to create device\n"));

		return status;

	}

	status = IoCreateSymbolicLink(&usSymbolicName, &usDeivceName);

	if (!NT_SUCCESS(status)) {

		IoDeleteDevice(pdeojb);

		KdPrint(("[LsMemory]:failed to create symbolic name\n"));

		return status;
	}

	KdPrint(("[LsMemory]:Create Link Success\n"));

	return status;

}

// 转发创建关闭
NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

typedef struct _PROCESS_MEMORY_OPERATION
{
	ULONG_PTR ProcessId;
	PVOID Address;
	PVOID Buffer;
	ULONG Size;
} PROCESS_MEMORY_OPERATION, * PPROCESS_MEMORY_OPERATION;

// Ioc通讯

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG ulControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID pBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG ulBufferSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;

    switch (ulControlCode) {
    case IoctlIoMemoryCard:
        KdPrint(("卡密验证!\n"));
        break;
    case IoctlIoMemoryReadWriteMod:
        KdPrint(("读写模式!\n"));
        break;
    case IoctlIoMemoryModuleAddress:
        KdPrint(("取模块地址!\n"));
        break;
    case IoctlIoMemoryRead:
        KdPrint(("读取内存!\n"));
        break;
    case IoctlIoMemoryWrite:
        KdPrint(("写入内存!\n"));
        break;
    case IoctlIoMemoryAlloc:
        KdPrint(("申请/释放内存!\n"));
        break;
    case IoctlIoMemoryHiddenProcess:
        KdPrint(("隐藏进程!\n"));
        break;
    case IoctlIoMemoryProtectProcess:
        KdPrint(("保护进程!\n"));
        break;
    default:
        KdPrint(("无效的 IOCTL 代码: 0x%X\n", ulControlCode));
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
}

pIrp->IoStatus.Information = ulBufferSize;
pIrp->IoStatus.Status = status;
IoCompleteRequest(pIrp, IO_NO_INCREMENT);
return status;
}

// 驱动卸载
void DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("[LsMemory]:Unload Successly\r\n"));
	IoDeleteSymbolicLink(&usSymbolicName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

// 驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("[LsMemory]:Driver Load!\n"));

	pDrvObj->DriverUnload = DriverUnload;

	status = InitDeviceSymbolic(pDrvObj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

    pDrvObj->MajorFunction[IRP_MJ_CREATE] = pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

	return status;
}