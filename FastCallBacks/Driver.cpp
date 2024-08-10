#include "Callbacks.h"
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY listEntry;
        ULONG64 __Undefined1;
        ULONG64 __Undefined2;
        ULONG64 __Undefined3;
        ULONG64 NonPagedDebugInfo;
        ULONG64 DllBase;
        ULONG64 EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG   Flags;
        USHORT  LoadCount;
        USHORT  __Undefined5;
        ULONG64 __Undefined6;
        ULONG   CheckSum;
        ULONG   __padding1;
        ULONG   TimeDateStamp;
        ULONG   __padding2;
    } KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
    typedef struct _KLDR_DATA_TABLE_ENTRY
    {
        LIST_ENTRY listEntry;
        ULONG unknown1;
        ULONG unknown2;
        ULONG unknown3;
        ULONG unknown4;
        ULONG unknown5;
        ULONG unknown6;
        ULONG unknown7;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG   Flags;
    } KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

    PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    pLdrData->Flags = pLdrData->Flags | 0x20;

    return TRUE;
}

Callbacks* _Callbacks;
void DriverUnload(PDRIVER_OBJECT drive_object)
{
    DbgPrint("[+]Try to UnEnabled Fast Callbacks....");
    _Callbacks->EnabledCallbacks(false);
    DbgPrint("[+]Fast Callback Driver Unload Success");
}
extern "C" NTSTATUS DriverMain(PDRIVER_OBJECT drive_object, PUNICODE_STRING path)
{
    DbgPrint("[+]Fast Callback Driver Load Success");
    NTSTATUS status;
    if (BypassCheckSign(drive_object)) {
        DbgPrint("[+]Bypass CheckSign Success");
        DbgPrint("[+]Try to Enabled Fast Callbacks....");
        _Callbacks->InitializeListEntryHead();
        _Callbacks->AddSafePid(12436);
        _Callbacks->EnabledCallbacks(true);
    }
    drive_object->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
