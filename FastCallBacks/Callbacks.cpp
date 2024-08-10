#include "Callbacks.h"
#include <devioctl.h>
LARGE_INTEGER Cookie;
extern "C" NTKERNELAPI PVOID NTAPI PsGetCurrentProcessWow64Process();
extern "C" NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
extern "C" NTKERNELAPI UCHAR * NTAPI PsGetProcessImageFileName(
	__in PEPROCESS Process
);
extern "C" NTKERNELAPI NTSTATUS NTAPI NtQueryInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);
extern "C" NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationProcess(
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
);
bool Get_Process_Image(HANDLE Process_Handle, UNICODE_STRING* Process_Path)
{
	NTSTATUS status = 0;
	ULONG Query_Return_Lenght = 0;
	UNICODE_STRING* temp_process_image_name = nullptr;
	FILE_OBJECT* process_image_file_object = nullptr;
	DEVICE_OBJECT* process_image_device_object = nullptr;
	OBJECT_NAME_INFORMATION* process_image_object_name = nullptr;

	//get full image name
	status = ZwQueryInformationProcess(Process_Handle, ProcessImageFileName,
		nullptr, 0, &Query_Return_Lenght);
	temp_process_image_name = (UNICODE_STRING*)new char[Query_Return_Lenght];
	RtlZeroMemory(temp_process_image_name, Query_Return_Lenght);
	//frist call ZwQueryInformationProcess get how long memory for we need
	status = ZwQueryInformationProcess(Process_Handle, ProcessImageFileName,
		temp_process_image_name, Query_Return_Lenght, &Query_Return_Lenght);
	if (!NT_SUCCESS(status))
	{
		goto Clean;
	}

	//conversion the image path
	status = IoGetDeviceObjectPointer(temp_process_image_name, SYNCHRONIZE,
		&process_image_file_object, &process_image_device_object);
	if (!NT_SUCCESS(status))
	{
		goto Clean;
	}
	status = IoQueryFileDosDeviceName(process_image_file_object, &process_image_object_name);
	if (!NT_SUCCESS(status))
	{
		goto Clean;
	}
	Process_Path->Length = process_image_object_name->Name.Length;
	Process_Path->MaximumLength = process_image_object_name->Name.MaximumLength;
	Process_Path->Buffer = (PWCH)new char[Process_Path->MaximumLength];
	RtlCopyMemory(Process_Path->Buffer,
		process_image_object_name->Name.Buffer, Process_Path->MaximumLength);

	ExFreePool(process_image_object_name);
	delete[](char*)temp_process_image_name;
	ObDereferenceObject(process_image_file_object);
	return true;
Clean:
	if (process_image_object_name)
	{
		ExFreePool(process_image_object_name);
	}
	if (temp_process_image_name)
	{
		delete[](char*)temp_process_image_name;
	}
	if (process_image_file_object)
	{
		ObDereferenceObject(process_image_file_object);
	}
	return false;
}
#define RegisterObProcessCallBack 1
#define RegisterObThreadCallBack 2
#define RegisterObFileCallBack 3
PVOID ObProcessHandle;
PVOID ObThreadHandle;
PVOID ObFileHandle;
NTSTATUS Callbacks::EnabledObCallBack(ULONG Option) {
	if (Option == RegisterObProcessCallBack) {
		OB_CALLBACK_REGISTRATION obReg;
		OB_OPERATION_REGISTRATION opReg;
		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321000");
		memset(&opReg, 0, sizeof(opReg));
		opReg.ObjectType = PsProcessType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FastOnPreOpenProcess;
		obReg.OperationRegistration = &opReg;
		return ObRegisterCallbacks(&obReg, &ObProcessHandle);
	}
	if (Option == RegisterObThreadCallBack) {
		OB_CALLBACK_REGISTRATION obReg;
		OB_OPERATION_REGISTRATION opReg;
		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321000");
		memset(&opReg, 0, sizeof(opReg));
		opReg.ObjectType = PsThreadType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FastOnPreOpenThread;
		obReg.OperationRegistration = &opReg;
		return ObRegisterCallbacks(&obReg, &ObThreadHandle);
	}
	if (Option == RegisterObThreadCallBack) {
		OB_CALLBACK_REGISTRATION obReg;
		OB_OPERATION_REGISTRATION opReg;
		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321000");
		memset(&opReg, 0, sizeof(opReg));
		opReg.ObjectType = IoFileObjectType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&FastOnFilePreCallBack;
		obReg.OperationRegistration = &opReg;
		return ObRegisterCallbacks(&obReg, &ObFileHandle);
	}
}
NTSTATUS Callbacks::EnabledCallbacks(bool isEnabled) {
	NTSTATUS Status = STATUS_SUCCESS;
	if (isEnabled) {
		Status = PsSetCreateProcessNotifyRoutineEx(
			(PCREATE_PROCESS_NOTIFY_ROUTINE_EX)FastCreateProcessNotifyEx,
			FALSE
		);
        if (NT_SUCCESS(Status)) {
            DbgPrint("[+]Install CreateProcessNotifyEx Success ! ! ! ");
        }
		Status = PsSetCreateThreadNotifyRoutine(
			(PCREATE_THREAD_NOTIFY_ROUTINE)FastThreadNotify
		);
		if (NT_SUCCESS(Status)) {
			DbgPrint("[+]Install ThreadNotify Success ! ! ! ");
		}

		Status = EnabledObCallBack(RegisterObProcessCallBack);
		Status = EnabledObCallBack(RegisterObThreadCallBack);
		Status = EnabledObCallBack(RegisterObFileCallBack);
		if (NT_SUCCESS(Status)) {
			DbgPrint("[+]Install Ob CallBacks Success ! ! ! ");
		}
	//	Status= CmRegisterCallback((PEX_CALLBACK_FUNCTION)FastRegistryCallback, NULL, &Cookie);
	//	if (NT_SUCCESS(Status)) {
	//		DbgPrint("[+]Install CmRegisterCallback Success ! ! ! ");
	//	}
	}
	else {
		Status = PsSetCreateProcessNotifyRoutineEx(
			(PCREATE_PROCESS_NOTIFY_ROUTINE_EX)FastCreateProcessNotifyEx,
			TRUE
		);
		if (NT_SUCCESS(Status)) {
			DbgPrint("[+]UnInstall CreateProcessNotifyEx Success ! ! ! ");
		}
		Status=PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)FastThreadNotify);
		if (NT_SUCCESS(Status)) {
			DbgPrint("[+]UnInstall ThreadNotify Success ! ! ! ");
		}
		if (ObProcessHandle) {
			ObUnRegisterCallbacks(ObProcessHandle);
		}
		if (ObThreadHandle) {
			ObUnRegisterCallbacks(ObThreadHandle);
		}
		if (ObFileHandle) {
			ObUnRegisterCallbacks(ObFileHandle);
		}
		DbgPrint("[+]UnInstall Ob CallBacks Success ! ! ! ");
		//Status = CmUnRegisterCallback(Cookie);
	//	if (NT_SUCCESS(Status)) {
	//		DbgPrint("[+]UnInstall CmUnRegisterCallback Success ! ! ! ");
	//	}
	}
	return Status;
}
#pragma region Actions ListEntry
LIST_ENTRY SafePidListHead;
KMUTEX SafePidListMutex;  // 用于同步的互斥量



void Callbacks::InitializeListEntryHead() {
	// 初始化链表头
	InitializeListHead(&SafePidListHead);
	// 初始化互斥量
	KeInitializeMutex(&SafePidListMutex, 0);
}

NTSTATUS Callbacks::AddSafePid(ULONG64 Pid) {
	NTSTATUS status;
	PSAFE_PID_ENTRY entry;

	// 等待互斥量，确保线程安全
	status = KeWaitForSingleObject(&SafePidListMutex, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_WAIT_0) {
		return status;  // 返回等待互斥量时的错误状态
	}

	// 分配内存以存储新的条目
	entry = (PSAFE_PID_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(SAFE_PID_ENTRY), 'Safp');
	if (entry == NULL) {
		KeReleaseMutex(&SafePidListMutex, FALSE);
		return STATUS_INSUFFICIENT_RESOURCES;  // 返回内存不足错误状态
	}

	// 初始化条目并插入链表
	entry->Pid = Pid;
	InsertTailList(&SafePidListHead, &entry->ListEntry);

	// 释放互斥量
	KeReleaseMutex(&SafePidListMutex, FALSE);

	return STATUS_SUCCESS;
}
NTSTATUS Callbacks::RemoveSafePid(ULONG64 Pid) {
	NTSTATUS status;

	// 等待互斥量，确保线程安全
	status = KeWaitForSingleObject(&SafePidListMutex, Executive, KernelMode, FALSE, NULL);
	if (status != STATUS_WAIT_0) {
		return status;  // 返回等待互斥量时的错误状态
	}

	// 遍历链表，查找并移除条目
	PLIST_ENTRY entry = SafePidListHead.Flink;
	while (entry != &SafePidListHead) {
		PSAFE_PID_ENTRY pidEntry = CONTAINING_RECORD(entry, SAFE_PID_ENTRY, ListEntry);
		if (pidEntry->Pid == Pid) {
			RemoveEntryList(&pidEntry->ListEntry);  // 从链表中移除条目
			ExFreePoolWithTag(pidEntry, 'Safp');    // 释放内存

			// 释放互斥量
			KeReleaseMutex(&SafePidListMutex, FALSE);

			return STATUS_SUCCESS;
		}
		entry = entry->Flink;
	}

	// 释放互斥量
	KeReleaseMutex(&SafePidListMutex, FALSE);

	return STATUS_NOT_FOUND;  // 未找到匹配的 PID
}
BOOLEAN Callbacks::IsPidSafe(ULONG64 Pid) {
	NTSTATUS status;
	BOOLEAN isSafe = FALSE;

	status = KeWaitForSingleObject(&SafePidListMutex, Executive, KernelMode, FALSE, NULL);
	if (status == STATUS_WAIT_0) {
		PLIST_ENTRY entry = SafePidListHead.Flink;
		while (entry != &SafePidListHead) {
			PSAFE_PID_ENTRY pidEntry = CONTAINING_RECORD(entry, SAFE_PID_ENTRY, ListEntry);
			if (pidEntry->Pid == Pid) {
				isSafe = TRUE;
				break;
			}
			entry = entry->Flink;
		}

		KeReleaseMutex(&SafePidListMutex, FALSE);
	}

	return isSafe;
}



void Callbacks::ClearMemory() {
	NTSTATUS status;
	PLIST_ENTRY entry;

	// 等待并获取 SafePidListMutex 互斥体
	status = KeWaitForSingleObject(&SafePidListMutex, Executive, KernelMode, FALSE, NULL);
	if (status == STATUS_WAIT_0) {
		// 清空 SafePidListHead 链表
		entry = SafePidListHead.Flink;
		while (entry != &SafePidListHead) {
			PSAFE_PID_ENTRY pidEntry = CONTAINING_RECORD(entry, SAFE_PID_ENTRY, ListEntry);
			entry = entry->Flink;  // 保存下一个条目的指针

			RemoveEntryList(&pidEntry->ListEntry);  // 从链表中移除条目
			ExFreePoolWithTag(pidEntry, 'Safp');    // 释放内存
		}

		// 释放 SafePidListMutex 互斥体
		KeReleaseMutex(&SafePidListMutex, FALSE);
	}
	else {
		// 互斥体获取失败，返回
		return;
	}
}
#pragma endregion



void Callbacks::FastCreateProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL)
    {
		WCHAR Path[260];
		WCHAR Name[260];

		HANDLE handle;
		OBJECT_ATTRIBUTES ObjectAttributes;
		CLIENT_ID clientid;
		InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
		clientid.UniqueProcess = (HANDLE)ProcessId;
		clientid.UniqueThread = 0;
		if (NT_SUCCESS(ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid)))
		{
			UNICODE_STRING temp_str;
			if (Get_Process_Image(handle, &temp_str))
			{
				RtlCopyMemory(Path, temp_str.Buffer, temp_str.MaximumLength);
				delete temp_str.Buffer;
			}
		}
		ZwClose(handle);
		PEPROCESS TargetProcess;
		PsLookupProcessByProcessId(ProcessId,&TargetProcess);
		if (TargetProcess) {
			ULONG64 ParentPid = (ULONG64)PsGetProcessInheritedFromUniqueProcessId(TargetProcess);
			RtlCopyMemory(Name, PsGetProcessImageFileName(TargetProcess), 15);
			UNICODE_STRING PathString;
			RtlInitUnicodeString(&PathString, Path);

			DbgPrint("[FastCallBack] PID : %llu | PPID : %d | EPROCESS : 0x%p | Path : %wZ\n",
				(ULONG64)ProcessId,
				ParentPid,
				TargetProcess,
				&PathString
			);
			//CreateInfo->ParentProcessId 这是父进程PID
			//CreateInfo->ImageFileName 这是路径
			ObDereferenceObject(TargetProcess);
		}
		else{
			DbgPrint("[FastCallBack] PID : %d | PPID : %d  | EPROCESS : 0x%p | Path : %wZ",
				(ULONG64)ProcessId,
				Process,
				CreateInfo->ParentProcessId,
				CreateInfo->ImageFileName);
		}

        if (wcsstr(Path, L"HipsMain.exe"))
        {
            CreateInfo->CreationStatus = STATUS_VIRUS_DELETED;
        }
		//这里其实不需要这么麻烦 只是自己想写而已qwq
    }
    else
    {
		//这是是退出
    }
}
void Callbacks::FastThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
	if (Create) {
		ULONG ThreadId_ = HandleToUlong(ThreadId);
		ULONG CreateProcessId = HandleToUlong(PsGetCurrentProcessId());
		ULONG ToProcessId = HandleToUlong(ProcessId);

		if (CreateProcessId != ToProcessId && CreateProcessId != 4) {
			//不属于本身 创建者不为4
		   // KdPrint(("检测到远程线程注入,tid %d ,cpid %d , bpid %d\n", item->Data.ThreadId, item->Data.Create_ProcessId, item->Data.Belong_ProcessId));
			//CreateProcessId为注入者
			//ToProcessId为被注入者
			WCHAR Path[260];
			PEPROCESS TargetProcess;
			PsLookupProcessByProcessId(ProcessId, &TargetProcess);
			if (TargetProcess) {
				HANDLE handle;
				OBJECT_ATTRIBUTES ObjectAttributes;
				CLIENT_ID clientid;
				InitializeObjectAttributes(&ObjectAttributes, 0, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
				clientid.UniqueProcess = (HANDLE)ProcessId;
				clientid.UniqueThread = 0;
				if (NT_SUCCESS(ZwOpenProcess(&handle, PROCESS_ALL_ACCESS, &ObjectAttributes, &clientid)))
				{
					UNICODE_STRING temp_str;
					if (Get_Process_Image(handle, &temp_str))
					{
						RtlCopyMemory(Path, temp_str.Buffer, temp_str.MaximumLength);
						delete temp_str.Buffer;
					}
				}
				ZwClose(handle);
				UNICODE_STRING PathString;
				RtlInitUnicodeString(&PathString, Path);
				DbgPrint("[+]INJECT PROCESS BLOCKED ! ! ! | Tid : %d | ProcessId : %ld | EPROCESS : 0x%p | Path : %wZ | TargetProcessId : %ld", 
					ThreadId_,
					CreateProcessId, 
					&PathString,
					ToProcessId);

			}
		}

	}
}
UNICODE_STRING GetFilePathByFileObject(PVOID FileObject)
{
	POBJECT_NAME_INFORMATION ObjetNameInfor;
	if (NT_SUCCESS(IoQueryFileDosDeviceName((PFILE_OBJECT)FileObject, &ObjetNameInfor)))
	{
		return ObjetNameInfor->Name;
	}
}
OB_PREOP_CALLBACK_STATUS Callbacks::FastOnFilePreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNICODE_STRING uniDosName;
	UNICODE_STRING uniFilePath;
	PFILE_OBJECT FileObject = (PFILE_OBJECT)OperationInformation->Object;
	HANDLE CurrentProcessId = PsGetCurrentProcessId();

	// 确保对象类型是文件对象
	if (OperationInformation->ObjectType != *IoFileObjectType) {
		return OB_PREOP_SUCCESS;
	}

	// 确保不是内核句柄
	if (OperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}

	// 过滤无效指针
	if (FileObject->FileName.Buffer == NULL ||
		!MmIsAddressValid(FileObject->FileName.Buffer) ||
		FileObject->DeviceObject == NULL ||
		!MmIsAddressValid(FileObject->DeviceObject)) {
		return OB_PREOP_SUCCESS;
	}

	// 获取文件路径
	uniFilePath = GetFilePathByFileObject(FileObject);
	if (uniFilePath.Buffer == NULL || uniFilePath.Length == 0) {
		return OB_PREOP_SUCCESS;
	}

	if (wcsstr(uniFilePath.Buffer, L"Test.txt"))
	{
		if (FileObject->DeleteAccess == TRUE || FileObject->WriteAccess == TRUE)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			{
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			}
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
			}
		}
	}
	if (NT_SUCCESS(RtlVolumeDeviceToDosName(FileObject->DeviceObject, &uniDosName))) {
		DbgPrint("PID : %ld File : %wZ  %wZ\r\n", (ULONG64)CurrentProcessId, &uniDosName, &uniFilePath);
	}
	else {
		DbgPrint("PID : %ld File : %wZ (Volume Name Conversion Failed)\r\n", (ULONG64)CurrentProcessId, &uniFilePath);
	}

	return OB_PREOP_SUCCESS;
}
OB_PREOP_CALLBACK_STATUS Callbacks::FastOnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}

	auto Process = (PEPROCESS)OperationInformation->Object;
	auto pid = HandleToULong(PsGetProcessId(Process));
	if (IsPidSafe(pid)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
	}

	return OB_PREOP_SUCCESS;
}
OB_PREOP_CALLBACK_STATUS Callbacks::FastOnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->KernelHandle) {
		return OB_PREOP_SUCCESS;
	}


	PETHREAD thread = (PETHREAD)OperationInformation->Object;
	ULONG tid = HandleToULong(PsGetThreadId(thread));
	ULONG ownerPid = HandleToULong(PsGetThreadProcessId(thread));
	ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

	// To avoid a situation when a process dies and the thread needs to be closed but it isn't closed, if the killer is its owning process, let it be killed.
	if (callerPid == ownerPid || callerPid == 4 || callerPid == 0) {
		return OB_PREOP_SUCCESS;
	}
	if (IsPidSafe(ownerPid)) {
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
	}
	return OB_PREOP_SUCCESS;
}
#define REG_TAG 'RgT'
BOOLEAN GetNameForRegistryObject(
	_Out_	 PUNICODE_STRING pRegistryPath,
	_In_	 PUNICODE_STRING pPartialRegistryPath,
	_In_	 PVOID pRegistryObject
)
{
	UNREFERENCED_PARAMETER(pPartialRegistryPath);
	BOOLEAN ret = FALSE;
	if ((!MmIsAddressValid(pRegistryObject)) || (!pRegistryObject))
		return ret;
	else
	{
		NTSTATUS Status = STATUS_SUCCESS;
		ULONG ReturnLen = 0;
		POBJECT_NAME_INFORMATION NameInfo = NULL;
		Status = ObQueryNameString(
			pRegistryObject,
			NameInfo, 0,
			&ReturnLen);
		if (Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(
				NonPagedPool, ReturnLen, REG_TAG);
			if (NameInfo)
			{
				Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
				if (NT_SUCCESS(Status))
				{
					ret = TRUE;
					RtlCopyUnicodeString(pRegistryPath, &(NameInfo->Name));
				}
				ExFreePoolWithTag(NameInfo, REG_TAG);
			}
			else
				ret = FALSE;
		}
	}
	return ret;
}
NTSTATUS Callbacks::FastRegistryCallback(
	_In_ PVOID CallbackContext,
	_In_ PVOID Argument1,
	_In_ PVOID Argument2
)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING RegPath;
	RegPath.Length = 0;
	RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
	RegPath.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, RegPath.MaximumLength, REG_TAG);
	if (!RegPath.Buffer) {
		return Status;
	}
	GetNameForRegistryObject(
		&RegPath,
		NULL,
		((PREG_DELETE_KEY_INFORMATION)Argument2)->Object
	);
	PUNICODE_STRING ValueKey = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->ValueName;
	RtlAppendUnicodeToString(&RegPath, L"\\");
	RtlAppendUnicodeStringToString(&RegPath, ValueKey);
	switch ((LONG)Argument1)
	{
		//键删除保护
	case RegNtPreDeleteValueKey: {
		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreDeleteKey: {

		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreSetValueKey: {

		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Debugger")) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (wcsstr(RegPath.Buffer, L"Software\\Classes\\ShellExec_RunAs\\command")) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (wcsstr(RegPath.Buffer, L"Software\\Classes\\ShellExec_RunAs")) {
			Status = STATUS_ACCESS_DENIED;
		}
		//AutoStartExtensibilityPoints
		//HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutostartApproved\Run
		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutostartApproved\\Run")) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreRenameKey: {
		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	case RegNtPreCreateKey: {
		if (wcsstr(RegPath.Buffer,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) {
			Status = STATUS_ACCESS_DENIED;
		}
		if (wcsstr(RegPath.Buffer, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\")) {
			Status = STATUS_ACCESS_DENIED;
		}
		break;
	}
	default:
		break;
	}
	ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
	return Status;
}