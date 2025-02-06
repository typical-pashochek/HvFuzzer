#pragma once

#define HV_FUZZER_DEVICE 0x00001111

#define IOCTL_SEND_MESSAGE CTL_CODE(HV_FUZZER_DEVICE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MSR_READ CTL_CODE(HV_FUZZER_DEVICE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CPUID CTL_CODE(HV_FUZZER_DEVICE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HYPERCALL CTL_CODE(HV_FUZZER_DEVICE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTERCEPT CTL_CODE(HV_FUZZER_DEVICE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Indicates to driver, to fill NonPagedPool page with ptrs to itself
//
#define USE_GPA_MEM_FILL            0x110000ff00

//
// Fill allocated kernel NonPagedPool page with 0's
//
#define USE_GPA_MEM_NOFILL_0        0x1100000000
#define USE_GPA_MEM_NOFILL_1        0x1100000001
#define USE_GPA_MEM_BIT_RANGE_LOOP  0x1100000002

typedef struct _CPU_REG_32
{
    UINT32 eax;
    UINT32 ebx;
    UINT32 ecx;
    UINT32 edx;
} CPU_REG_32, * PCPU_REG_32;

typedef struct _UINT128
{
    UINT64 lower;
    UINT64 upper;
} UINT128, * PUINT128;

typedef struct _CPU_REG_64
{
    UINT64 rax;
    UINT64 rbx;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT128 xmm0;
    UINT128 xmm1;
    UINT128 xmm2;
    UINT128 xmm3;
    UINT128 xmm4;
    UINT128 xmm5;
} CPU_REG_64, * PCPU_REG_64;

#pragma warning(disable:4214)
#pragma warning(disable:4201)
#pragma pack(push)
#pragma pack(push, 1)

//
// HyperV
//
typedef UINT16 HV_STATUS;
typedef UINT64 HV_PARTITION_ID;
typedef UINT64 HV_GPA;
typedef UINT64 HV_ADDRESS_SPACE_ID;
typedef HV_PARTITION_ID* PHV_PARTITION_ID;
typedef UINT64 HV_NANO100_TIME;
typedef HV_NANO100_TIME* PHV_NANO100_TIME;
typedef UINT64 HV_PARTITION_PROPERTY;
typedef HV_PARTITION_PROPERTY* PHV_PARTITION_PROPERTY;
typedef UINT8 HV_INTERCEPT_ACCESS_TYPE_MASK;
typedef UINT32 HV_VP_INDEX;
typedef UINT32 HV_INTERRUPT_VECTOR;
typedef HV_INTERRUPT_VECTOR* PHV_INTERRUPT_VECTOR;
typedef UINT16 HV_X64_IO_PORT;

//
// As defined in the MS TLFS - the Hypercall 64b value
// 
// 63:60|59:48        |47:44|43:32    |31:27|26:17             |16  |15:0
// -----+-------------+-----+---------+-----+------------------+----+---------
// Rsvd |Rep start idx|Rsvd |Rep count|Rsvd |Variable header sz|Fast|Call Code
// 4b   |12b          |4b   |12b      |5 b  |9b                |1b  |16b
//

typedef volatile union
{
    struct
    {
        UINT16 callCode : 16;
        UINT16 fastCall : 1;
        UINT16 variableHeaderSize : 9;
        UINT16 rsvd1 : 5;
        UINT16 repCnt : 12;
        UINT16 rsvd2 : 4;
        UINT16 repStartIdx : 12;
        UINT16 rsvd3 : 4;
    };
    UINT64 AsUINT64;
} HV_X64_HYPERCALL_INPUT, * PHV_X64_HYPERCALL_INPUT;
C_ASSERT(sizeof(HV_X64_HYPERCALL_INPUT) == 8);

typedef union _HV_X64_HYPERCALL_OUTPUT
{
    struct
    {
        HV_STATUS CallStatus;
        UINT16 dontCare1;
        UINT32 ElementsProcessed : 12;
        UINT32 dontCare2 : 20;
    };
    UINT64 AsUINT64;
} HV_X64_HYPERCALL_OUTPUT, * PHV_X64_HYPERCALL_OUTPUT;

//
// TLFS Hypercall Result Value returned from hypercall
//
typedef volatile union
{
    struct
    {
        UINT16 result : 16;
        UINT16 rsvd1 : 16;
        UINT32 repComplete : 12;
        UINT32 rsvd2 : 20;
    };
    UINT64 AsUINT64;
} HYPERCALL_RESULT_VALUE;
C_ASSERT(sizeof(HYPERCALL_RESULT_VALUE) == 8);


#pragma pack(pop)
#pragma warning(default:4201) 
#pragma warning(disable:4214)

typedef struct _HYPERCALL_DATA
{
    HV_X64_HYPERCALL_INPUT hypercallInput;
    CHAR inputParameter[0x1000];
} HYPERCALL_DATA, *PHYPERCALL_DATA;

