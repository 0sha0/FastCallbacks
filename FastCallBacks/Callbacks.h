#pragma once
#include <ntifs.h>
#include <vector>
#include <wdm.h>
#define PROCESS_QUERY_LIMITED_INFORMATION	(0x1000)
#define PROTECTED_PROCESS_MASK	0x00000800
// Exclude false positive matches in the KPROCESS/Pcb header
#ifdef _M_AMD64
#define PS_SEARCH_START				0x600
#else
#define PS_SEARCH_START				0x200
#endif
#define PROCESS_TERMINATE                  (0x0001)
#define PROCESS_CREATE_THREAD              (0x0002)
#define PROCESS_SET_SESSIONID              (0x0004)
#define PROCESS_VM_OPERATION               (0x0008)
#define PROCESS_VM_READ                    (0x0010)
#define PROCESS_VM_WRITE                   (0x0020)
#define PROCESS_DUP_HANDLE                 (0x0040)
#define PROCESS_CREATE_PROCESS             (0x0080)
#define PROCESS_SET_QUOTA                  (0x0100)
#define PROCESS_SET_INFORMATION            (0x0200)
#define PROCESS_QUERY_INFORMATION          (0x0400)
#define PROCESS_SUSPEND_RESUME             (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)
typedef struct _SAFE_PID_ENTRY {
	LIST_ENTRY ListEntry;
	ULONG64 Pid;
} SAFE_PID_ENTRY, * PSAFE_PID_ENTRY;


class Callbacks
{
public:
	void InitializeListEntryHead();
	NTSTATUS  AddSafePid(ULONG64 Pid);
	 NTSTATUS  RemoveSafePid(ULONG64 Pid);
	 void ClearMemory();
	NTSTATUS EnabledCallbacks(bool isEnabled);
private:	
	static BOOLEAN IsPidSafe(ULONG64 Pid);
	NTSTATUS EnabledObCallBack(ULONG Option);
	static NTSTATUS FastRegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
	static void FastCreateProcessNotifyEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	static void FastThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create);
	static OB_PREOP_CALLBACK_STATUS FastOnFilePreCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
	static OB_PREOP_CALLBACK_STATUS FastOnPreOpenProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
	static OB_PREOP_CALLBACK_STATUS FastOnPreOpenThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
};
