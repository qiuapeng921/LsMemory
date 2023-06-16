#include <ntddk.h>

#include "标头.h"
#include "读写.h"


NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	KdPrint(("调度创建关闭!\n"));
	UNREFERENCED_PARAMETER(pDevObj);
	UNREFERENCED_PARAMETER(pIrp);

	pIrp->IoStatus.Information = 0;
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	ULONG i = 0, code = 0, len = 0, size = 0;
	PIO_STACK_LOCATION stack = NULL;

	stack = IoGetCurrentIrpStackLocation(pIrp);
	code = stack->Parameters.DeviceIoControl.IoControlCode;

	switch (code) {
	case IOCTL_GET_SECTION_ADDRESS:
		KdPrint(("获取段地址!\n"));
		break;
	case IOCTL_WRITE_MEMORY:
		KdPrint(("写内存!\n"));
		break;
	case IOCTL_ALLOCATE_MEMORY:
		KdPrint(("申请内存!\n"));
		break;
	case IOCTL_FREE_MEMORY:
		KdPrint(("释放内存!\n"));
		break;
	case IOCTL_MAP_MEMORY:
		KdPrint(("映射内存!\n"));
		break;
	case IOCTL_UNMAP_MEMORY:
		KdPrint(("取消映射内存!\n"));
		break;
	case IOCTL_DUMP_AND_RESET_CALLBACK:
		KdPrint(("转储和重置回调!\n"));
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

void DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	UNICODE_STRING usSymboName;

	KdPrint(("驱动卸载!\n"));
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoDeleteSymbolicLink(&usSymboName);
	if (pDrvObj->DeviceObject != NULL) {
		IoDeleteDevice(pDrvObj->DeviceObject);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	PDEVICE_OBJECT pFunObj = NULL;
	UNICODE_STRING usDeviceName;
	UNICODE_STRING usSymboName;
	UNREFERENCED_PARAMETER(pRegPath);

	KdPrint(("驱动加载!\n"));
	RtlInitUnicodeString(&usDeviceName, DRIVER_NAME);
	IoCreateDevice(pDrvObj, 0, &usDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pFunObj);
	RtlInitUnicodeString(&usSymboName, DEVICE_NAME);
	IoCreateSymbolicLink(&usSymboName, &usDeviceName);

	// pDrvObj->MajorFunction[IRP_MJ_CREATE] =
	pDrvObj->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
	pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDrvObj->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}