import random
import re
import json


hypercalls = {
    "HvSwitchVirtualAddressSpace": 0x0001,
    "HvFlushVirtualAddressSpace": 0x0002,
    "HvFlushVirtualAddressList": 0x0003,
    "HvGetLogicalProcessorRunTime": 0x0004,
    # Reserved 0x0005..0x0007
    "HvCallNotifyLongSpinWait": 0x0008,
    "HvCallParkedVirtualProcessors": 0x0009,
    "HvCallSyntheticClusterIpi": 0x000B,
    "HvCallModifyVtlProtectionMask": 0x000C,
    "HvCallEnablePartitionVtl": 0x000D,
    "HvCallDisablePartitionVtl": 0x000E,
    "HvCallEnableVpVtl": 0x000F,
    "HvCallDisableVpVtl": 0x0010,
    "HvCallVtlCall": 0x0011,
    "HvCallVtlReturn": 0x0012,
    "HvCallFlushVirtualAddressSpaceEx": 0x0013,
    "HvCallFlushVirtualAddressListEx": 0x0014,
    "HvCallSendSyntheticClusterIpiEx": 0x0015,
    # Reserved 0x0016..0x003F
    "HvCreatePartition": 0x0040,
    "HvInitializePartition": 0x0041,
    "HvFinalizePartition": 0x0042,
    "HvDeletePartition": 0x0043,
    "HvGetPartitionProperty": 0x0044,
    "HvSetPartitionProperty": 0x0045,
    "HvGetPartitionId": 0x0046,
    "HvGetNextChildPartition": 0x0047,
    "HvDepositMemory": 0x0048,
    "HvWithdrawMemory": 0x0049,
    "HvGetMemoryBalance": 0x004A,
    "HvMapGpaPages": 0x004B,
    "HvUnmapGpaPages": 0x004C,
    "HvInstallIntercept": 0x004D,
    "HvCreateVp": 0x004E,
    "HvDeleteVp": 0x004F,
    "HvGetVpRegisters": 0x0050,
    "HvSetVpRegisters": 0x0051,
    "HvTranslateVirtualAddress": 0x0052,
    "HvReadGpa": 0x0053,
    "HvWriteGpa": 0x0054,
    # Reserved 0x0055, 0x0057
    "HvClearVirtualInterrupt": 0x0056,
    "HvDeletePort": 0x0058,
    "HvConnectPort": 0x0059,
    "HvGetPortProperty": 0x005A,
    "HvDisconnectPort": 0x005B,
    "HvPostMessage": 0x005C,
    "HvSignalEvent": 0x005D,
    "HvSavePartitionState": 0x005E,
    "HvRestorePartitionState": 0x005F,
    "HvInitializeEventLogBufferGroup": 0x0060,
    "HvFinalizeEventLogBufferGroup": 0x0061,
    "HvCreateEventLogBuffer": 0x0062,
    "HvDeleteEventLogBuffer": 0x0063,
    "HvMapEventLogBuffer": 0x0064,
    "HvUnmapEventLogBuffer": 0x0065,
    "HvSetEventLogGroupSources": 0x0066,
    "HvReleaseEventLogBuffer": 0x0067,
    "HvFlushEventLogBuffer": 0x0068,
    "HvPostDebugData": 0x0069,
    "HvRetrieveDebugData": 0x006A,
    "HvResetDebugSession": 0x006B,
    "HvMapStatsPage": 0x006C,
    "HvUnmapStatsPage": 0x006D,
    "HvCallMapSparseGpaPages": 0x006E,
    "HvCallSetSystemProperty": 0x006F,
    "HvCallSetPortProperty": 0x0070,
    # Reserved 0x0071..0x0075
    "HvCallAddLogicalProcessor": 0x0076,
    "HvCallRemoveLogicalProcessor": 0x0077,
    "HvCallQueryNumaDistance": 0x0078,
    "HvCallSetLogicalProcessorProperty": 0x0079,
    "HvCallGetLogicalProcessorProperty": 0x007A,
    "HvCallGetSystemProperty": 0x007B,
    "HvCallMapDeviceInterrupt": 0x007C,
    "HvCallUnmapDeviceInterrupt": 0x007D,
    "HvCallRetargetDeviceInterrupt": 0x007E,
    # Reserved 0x007F
    "HvCallMapDevicePages": 0x0080,
    "HvCallUnmapDevicePages": 0x0081,
    "HvCallAttachDevice": 0x0082,
    "HvCallDetachDevice": 0x0083,
    "HvCallNotifyStandbyTransition": 0x0084,
    "HvCallPrepareForSleep": 0x0085,
    "HvCallPrepareForHibernate": 0x0086,
    "HvCallNotifyPartitionEvent": 0x0087,
    "HvCallGetLogicalProcessorRegisters": 0x0088,
    "HvCallSetLogicalProcessorRegisters": 0x0089,
    "HvCallQueryAssotiatedLpsforMca": 0x008A,
    "HvCallNotifyRingEmpty": 0x008B,
    "HvCallInjectSyntheticMachineCheck": 0x008C,
    "HvCallScrubPartition": 0x008D,
    "HvCallCollectLivedump": 0x008E,
    "HvCallDisableHypervisor": 0x008F,
    "HvCallModifySparseGpaPages": 0x0090,
    "HvCallRegisterInterceptResult": 0x0091,
    "HvCallUnregisterInterceptResult": 0x0092,
    "HvCallAssertVirtualInterrupt": 0x0094,
    "HvCallCreatePort": 0x0095,
    "HvCallConnectPort": 0x0096,
    "HvCallGetSpaPageList": 0x0097,
    # Reserved 0x0098..0x00AE
    "HvCallFlushGuestPhysicalAddressSpace": 0x00AF,
    "HvCallFlushGuestPhysicalAddressList": 0x00B0,
}


secure_services = {}

with open("secure_services.txt", 'r') as f:
        secure_services = json.load(f)

with open("hypercall_cases.txt", "w") as f:
    for sscn, arg_len in secure_services.items():
        arg_len_bytes = 0 if arg_len is None else arg_len * 8

        for i in range (1, 100):
            sscn_byte_array = int(sscn).to_bytes(2, byteorder='little')
            line = f"{0x11} {0} {0} {2:02x}{0:02x}{sscn_byte_array.hex()}{0:08x}{random.getrandbits(arg_len_bytes):06x}\n"
            f.write(line)
    
    for call_name, call_code in hypercalls.items():
        if call_code == 0x11:
            continue
        for fast_call in range (0, 1):
            for rep_cnt in range(0, 10):
                for arg_len in range(1, 100):
                    for i in range (1, 5):
                        line = f"{call_code} {fast_call} {rep_cnt} {random.getrandbits(arg_len):06x}\n"
                        f.write(line)
    