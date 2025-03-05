#ifdef PETHREAD
#undef PETHREAD
#endif
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName,
		PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress,
		SIZE_T BufferSizew, KPROCESSOR_MODE PreviouseMode,
		PSIZE_T ReturnSize);
}


namespace codes {
    constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
}
struct  Request {
    HANDLE procees_id;

    PVOID target;
    PVOID buffer;

    SIZE_T size;
    SIZE_T return_size;

};

NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);

	DbgPrint("[+]device control called.\n");

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
	auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

	if (stack_irp == nullptr || request == nullptr)
	{
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}
	static PEPROCESS target_process = nullptr;
	const ULONG control_code = stack_irp->Parameters.DeviceIoControl.IoControlCode;
	switch (control_code)
	{
	case codes::attach:
		DbgPrint("[+]attaching called.");

		status = PsLookupProcessByProcessId(request->procees_id, &target_process);
		break;
	case codes::read:
		if (target_process != nullptr)
		{
			DbgPrint("[+]read memory called.");
			status = MmCopyVirtualMemory(target_process, request->target,
				PsGetCurrentProcess(), request->buffer,
				request->size, KernelMode, &request->return_size);
		}
		break;

	case codes::write:
		if (target_process != nullptr)
		{
				DbgPrint("[+]write memory called.");

				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer,
				target_process, request->target,
				request->size, KernelMode, &request->return_size);
		}			break;


	default:
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = sizeof(Request);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}


VOID DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;

    DbgPrint("[+]DrvUnload Called !");

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\first_driver");

    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
}
NTSTATUS DrvUnsupported(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[*] This function is not supported :( !");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

//NTSTATUS DrvIoctlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
//{
//    UNREFERENCED_PARAMETER(DeviceObject);
//
//    DbgPrint("[*]asdasdads Successfully !");
//
//    Irp->IoStatus.Status = STATUS_SUCCESS;
//    Irp->IoStatus.Information = 0;
//    IoCompleteRequest(Irp, IO_NO_INCREMENT);
//
//    return STATUS_SUCCESS;
//}
//


NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
	DbgPrint("[+]creating driver called.");

	UNREFERENCED_PARAMETER(device_object);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}
NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
	DbgPrint("[+]closing driver called.");
	UNREFERENCED_PARAMETER(device_object);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS       NtStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;
    UNICODE_STRING DriverName, DosDeviceName;

    DbgPrint("[+]DriverEntry Called.");

    RtlInitUnicodeString(&DriverName, L"\\Device\\first_driver");
    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\first_driver");

    NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);




	if (NtStatus != STATUS_SUCCESS) {
		DbgPrint("[-] failed to create driver dvice.\n");
		return NtStatus;
	}
	DbgPrint("[+] driver device successfully created.\n");



	if (NtStatus == STATUS_SUCCESS)
	{
		DriverObject->DriverUnload = DrvUnload;
		DeviceObject->Flags |= IO_TYPE_DEVICE;
		DeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);



		for (int Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
		{
			DriverObject->MajorFunction[Index] = DrvUnsupported;
		}

		DbgPrint("[+] Setting Devices major functions.");
		DriverObject->MajorFunction[IRP_MJ_CLOSE] = close;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = create;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = device_control;

		//DriverObject->MajorFunction[IRP_MJ_READ] = DrvRead;
		//DriverObject->MajorFunction[IRP_MJ_WRITE] = DrvWrite;

		//DriverObject->DriverUnload = DrvUnload;

		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}
	else
	{
		DbgPrint("[-] There were some errors in creating device.");
	}


    return NtStatus;
}
