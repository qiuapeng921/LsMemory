#include <ntddk.h>

#include "Constant.h"

// #include "ReadMemory.h"
// #include "WriteMemory.h"
// #include "GetModuleBase.h"

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

// Ioc通讯
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	NTSTATUS status = STATUS_SUCCESS;
	ULONG i = 0, code = 0, len = 0, size = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	KdPrint(("[LsMemory]:failed to create device\n"));

	switch (code) {
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
		KdPrint(("无效的 IOCTL 代码: 0x%X\n", code));
		break;
	}

	pIrp->IoStatus.Information = len;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
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

	pDrvObj->MajorFunction[IRP_MJ_CREATE] =
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	
	return status;
}