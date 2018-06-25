// Copyright 2018 Cloudbase Solutions Srl
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

#![allow(non_camel_case_types)]

use std::os::raw::{c_int, c_longlong, c_uchar, c_uint, c_ushort, c_void};

pub type WHV_PARTITION_HANDLE = *mut c_void;
pub type HRESULT = c_int;
pub type UINT8 = c_uchar;
pub type UINT32 = c_uint;
pub type UINT64 = c_longlong;
pub type VOID = c_void;
pub type BOOL = c_int;
pub type UINT16 = c_ushort;

pub type WHV_GUEST_PHYSICAL_ADDRESS = UINT64;
pub type WHV_GUEST_VIRTUAL_ADDRESS = UINT64;

pub const S_OK: HRESULT = 0;
pub const E_INVALIDARG: HRESULT = -2147024809; // 0x80070057
pub const WHV_E_INSUFFICIENT_BUFFER: HRESULT = -2143878399; // 0x80370301
pub const WHV_E_INVALID_PARTITION_CONFIG: HRESULT = -2143878396; // 0x80370304
pub const WHV_E_GPA_RANGE_NOT_FOUND: HRESULT = -2143878395; // 0x80370305

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_PARTITION_PROPERTY_CODE {
    WHvPartitionPropertyCodeExtendedVmExits = 0x00000001,
    WHvPartitionPropertyCodeExceptionExitBitmap = 0x00000002,
    WHvPartitionPropertyCodeProcessorFeatures = 0x00001001,
    WHvPartitionPropertyCodeProcessorClFlushSize = 0x00001002,
    WHvPartitionPropertyCodeCpuidExitList = 0x00001003,
    WHvPartitionPropertyCodeCpuidResultList = 0x00001004,
    WHvPartitionPropertyCodeProcessorCount = 0x00001fff,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_CAPABILITY_CODE {
    // Capabilities of the API implementation
    WHvCapabilityCodeHypervisorPresent = 0x00000000,
    WHvCapabilityCodeFeatures = 0x00000001,
    WHvCapabilityCodeExtendedVmExits = 0x00000002,
    WHvCapabilityCodeExceptionExitBitmap = 0x00000003,

    // Capabilities of the system's processor
    WHvCapabilityCodeProcessorVendor = 0x00001000,
    WHvCapabilityCodeProcessorFeatures = 0x00001001,
    WHvCapabilityCodeProcessorClFlushSize = 0x00001002,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_PROCESSOR_VENDOR {
    WHvProcessorVendorAmd = 0x0000,
    WHvProcessorVendorIntel = 0x0001,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_RUN_VP_EXIT_REASON {
    WHvRunVpExitReasonNone = 0x00000000,

    // Standard exits caused by operations of the virtual processor
    WHvRunVpExitReasonMemoryAccess = 0x00000001,
    WHvRunVpExitReasonX64IoPortAccess = 0x00000002,
    WHvRunVpExitReasonUnrecoverableException = 0x00000004,
    WHvRunVpExitReasonInvalidVpRegisterValue = 0x00000005,
    WHvRunVpExitReasonUnsupportedFeature = 0x00000006,
    WHvRunVpExitReasonX64InterruptWindow = 0x00000007,
    WHvRunVpExitReasonX64Halt = 0x00000008,

    // Additional exits that can be configured through partition properties
    WHvRunVpExitReasonX64MsrAccess = 0x00001000,
    WHvRunVpExitReasonX64Cpuid = 0x00001001,
    WHvRunVpExitReasonException = 0x00001002,

    // Exits caused by the host
    WHvRunVpExitReasonCanceled = 0x00002001,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_X64_PENDING_INTERRUPTION_TYPE {
    WHvX64PendingInterrupt = 0,
    WHvX64PendingNmi = 2,
    WHvX64PendingException = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_X64_UNSUPPORTED_FEATURE_CODE {
    WHvUnsupportedFeatureIntercept = 1,
    WHvUnsupportedFeatureTaskSwitchTss = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_RUN_VP_CANCEL_REASON {
    WhvRunVpCancelReasonUser = 0, // Execution canceled by HvCancelRunVirtualProcessor
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_MAP_GPA_RANGE_FLAGS {
    WHvMapGpaRangeFlagNone = 0x00000000,
    WHvMapGpaRangeFlagRead = 0x00000001,
    WHvMapGpaRangeFlagWrite = 0x00000002,
    WHvMapGpaRangeFlagExecute = 0x00000004,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_REGISTER_NAME {
    // X64 General purpose registers
    WHvX64RegisterRax = 0x00000000,
    WHvX64RegisterRcx = 0x00000001,
    WHvX64RegisterRdx = 0x00000002,
    WHvX64RegisterRbx = 0x00000003,
    WHvX64RegisterRsp = 0x00000004,
    WHvX64RegisterRbp = 0x00000005,
    WHvX64RegisterRsi = 0x00000006,
    WHvX64RegisterRdi = 0x00000007,
    WHvX64RegisterR8 = 0x00000008,
    WHvX64RegisterR9 = 0x00000009,
    WHvX64RegisterR10 = 0x0000000A,
    WHvX64RegisterR11 = 0x0000000B,
    WHvX64RegisterR12 = 0x0000000C,
    WHvX64RegisterR13 = 0x0000000D,
    WHvX64RegisterR14 = 0x0000000E,
    WHvX64RegisterR15 = 0x0000000F,
    WHvX64RegisterRip = 0x00000010,
    WHvX64RegisterRflags = 0x00000011,

    // X64 Segment registers
    WHvX64RegisterEs = 0x00000012,
    WHvX64RegisterCs = 0x00000013,
    WHvX64RegisterSs = 0x00000014,
    WHvX64RegisterDs = 0x00000015,
    WHvX64RegisterFs = 0x00000016,
    WHvX64RegisterGs = 0x00000017,
    WHvX64RegisterLdtr = 0x00000018,
    WHvX64RegisterTr = 0x00000019,

    // X64 Table registers
    WHvX64RegisterIdtr = 0x0000001A,
    WHvX64RegisterGdtr = 0x0000001B,

    // X64 Control Registers
    WHvX64RegisterCr0 = 0x0000001C,
    WHvX64RegisterCr2 = 0x0000001D,
    WHvX64RegisterCr3 = 0x0000001E,
    WHvX64RegisterCr4 = 0x0000001F,
    WHvX64RegisterCr8 = 0x00000020,

    // X64 Debug Registers
    WHvX64RegisterDr0 = 0x00000021,
    WHvX64RegisterDr1 = 0x00000022,
    WHvX64RegisterDr2 = 0x00000023,
    WHvX64RegisterDr3 = 0x00000024,
    WHvX64RegisterDr6 = 0x00000025,
    WHvX64RegisterDr7 = 0x00000026,

    // X64 Floating Point and Vector Registers
    WHvX64RegisterXmm0 = 0x00001000,
    WHvX64RegisterXmm1 = 0x00001001,
    WHvX64RegisterXmm2 = 0x00001002,
    WHvX64RegisterXmm3 = 0x00001003,
    WHvX64RegisterXmm4 = 0x00001004,
    WHvX64RegisterXmm5 = 0x00001005,
    WHvX64RegisterXmm6 = 0x00001006,
    WHvX64RegisterXmm7 = 0x00001007,
    WHvX64RegisterXmm8 = 0x00001008,
    WHvX64RegisterXmm9 = 0x00001009,
    WHvX64RegisterXmm10 = 0x0000100A,
    WHvX64RegisterXmm11 = 0x0000100B,
    WHvX64RegisterXmm12 = 0x0000100C,
    WHvX64RegisterXmm13 = 0x0000100D,
    WHvX64RegisterXmm14 = 0x0000100E,
    WHvX64RegisterXmm15 = 0x0000100F,
    WHvX64RegisterFpMmx0 = 0x00001010,
    WHvX64RegisterFpMmx1 = 0x00001011,
    WHvX64RegisterFpMmx2 = 0x00001012,
    WHvX64RegisterFpMmx3 = 0x00001013,
    WHvX64RegisterFpMmx4 = 0x00001014,
    WHvX64RegisterFpMmx5 = 0x00001015,
    WHvX64RegisterFpMmx6 = 0x00001016,
    WHvX64RegisterFpMmx7 = 0x00001017,
    WHvX64RegisterFpControlStatus = 0x00001018,
    WHvX64RegisterXmmControlStatus = 0x00001019,

    // X64 MSRs
    WHvX64RegisterTsc = 0x00002000,
    WHvX64RegisterEfer = 0x00002001,
    WHvX64RegisterKernelGsBase = 0x00002002,
    WHvX64RegisterApicBase = 0x00002003,
    WHvX64RegisterPat = 0x00002004,
    WHvX64RegisterSysenterCs = 0x00002005,
    WHvX64RegisterSysenterEip = 0x00002006,
    WHvX64RegisterSysenterEsp = 0x00002007,
    WHvX64RegisterStar = 0x00002008,
    WHvX64RegisterLstar = 0x00002009,
    WHvX64RegisterCstar = 0x0000200A,
    WHvX64RegisterSfmask = 0x0000200B,

    WHvX64RegisterMsrMtrrCap = 0x0000200D,
    WHvX64RegisterMsrMtrrDefType = 0x0000200E,

    WHvX64RegisterMsrMtrrPhysBase0 = 0x00002010,
    WHvX64RegisterMsrMtrrPhysBase1 = 0x00002011,
    WHvX64RegisterMsrMtrrPhysBase2 = 0x00002012,
    WHvX64RegisterMsrMtrrPhysBase3 = 0x00002013,
    WHvX64RegisterMsrMtrrPhysBase4 = 0x00002014,
    WHvX64RegisterMsrMtrrPhysBase5 = 0x00002015,
    WHvX64RegisterMsrMtrrPhysBase6 = 0x00002016,
    WHvX64RegisterMsrMtrrPhysBase7 = 0x00002017,
    WHvX64RegisterMsrMtrrPhysBase8 = 0x00002018,
    WHvX64RegisterMsrMtrrPhysBase9 = 0x00002019,
    WHvX64RegisterMsrMtrrPhysBaseA = 0x0000201A,
    WHvX64RegisterMsrMtrrPhysBaseB = 0x0000201B,
    WHvX64RegisterMsrMtrrPhysBaseC = 0x0000201C,
    WHvX64RegisterMsrMtrrPhysBaseD = 0x0000201D,
    WHvX64RegisterMsrMtrrPhysBaseE = 0x0000201E,
    WHvX64RegisterMsrMtrrPhysBaseF = 0x0000201F,

    WHvX64RegisterMsrMtrrPhysMask0 = 0x00002040,
    WHvX64RegisterMsrMtrrPhysMask1 = 0x00002041,
    WHvX64RegisterMsrMtrrPhysMask2 = 0x00002042,
    WHvX64RegisterMsrMtrrPhysMask3 = 0x00002043,
    WHvX64RegisterMsrMtrrPhysMask4 = 0x00002044,
    WHvX64RegisterMsrMtrrPhysMask5 = 0x00002045,
    WHvX64RegisterMsrMtrrPhysMask6 = 0x00002046,
    WHvX64RegisterMsrMtrrPhysMask7 = 0x00002047,
    WHvX64RegisterMsrMtrrPhysMask8 = 0x00002048,
    WHvX64RegisterMsrMtrrPhysMask9 = 0x00002049,
    WHvX64RegisterMsrMtrrPhysMaskA = 0x0000204A,
    WHvX64RegisterMsrMtrrPhysMaskB = 0x0000204B,
    WHvX64RegisterMsrMtrrPhysMaskC = 0x0000204C,
    WHvX64RegisterMsrMtrrPhysMaskD = 0x0000204D,
    WHvX64RegisterMsrMtrrPhysMaskE = 0x0000204E,
    WHvX64RegisterMsrMtrrPhysMaskF = 0x0000204F,

    WHvX64RegisterMsrMtrrFix64k00000 = 0x00002070,
    WHvX64RegisterMsrMtrrFix16k80000 = 0x00002071,
    WHvX64RegisterMsrMtrrFix16kA0000 = 0x00002072,
    WHvX64RegisterMsrMtrrFix4kC0000 = 0x00002073,
    WHvX64RegisterMsrMtrrFix4kC8000 = 0x00002074,
    WHvX64RegisterMsrMtrrFix4kD0000 = 0x00002075,
    WHvX64RegisterMsrMtrrFix4kD8000 = 0x00002076,
    WHvX64RegisterMsrMtrrFix4kE0000 = 0x00002077,
    WHvX64RegisterMsrMtrrFix4kE8000 = 0x00002078,
    WHvX64RegisterMsrMtrrFix4kF0000 = 0x00002079,
    WHvX64RegisterMsrMtrrFix4kF8000 = 0x0000207A,

    WHvX64RegisterTscAux = 0x0000207B,

    // Interrupt / Event Registers
    WHvRegisterPendingInterruption = 0x80000000,
    WHvRegisterInterruptState = 0x80000001,
    WHvRegisterPendingEvent0 = 0x80000002,
    WHvRegisterPendingEvent1 = 0x80000003,
    WHvX64RegisterDeliverabilityNotifications = 0x80000004,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_TRANSLATE_GVA_FLAGS {
    WHvTranslateGvaFlagNone = 0x00000000,
    WHvTranslateGvaFlagValidateRead = 0x00000001,
    WHvTranslateGvaFlagValidateWrite = 0x00000002,
    WHvTranslateGvaFlagValidateExecute = 0x00000004,
    WHvTranslateGvaFlagPrivilegeExempt = 0x00000008,
    WHvTranslateGvaFlagSetPageTableBits = 0x00000010,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WHV_TRANSLATE_GVA_RESULT_CODE {
    WHvTranslateGvaResultSuccess = 0,

    // Translation failures
    WHvTranslateGvaResultPageNotPresent = 1,
    WHvTranslateGvaResultPrivilegeViolation = 2,
    WHvTranslateGvaResultInvalidPageTableFlags = 3,

    // GPA access failures
    WHvTranslateGvaResultGpaUnmapped = 4,
    WHvTranslateGvaResultGpaNoReadAccess = 5,
    WHvTranslateGvaResultGpaNoWriteAccess = 6,
    WHvTranslateGvaResultGpaIllegalOverlayAccess = 7,
    WHvTranslateGvaResultIntercept = 8,
}

#[allow(non_snake_case)]
#[derive(Copy, Clone)]
#[repr(C)]
pub union WHV_CAPABILITY {
    pub HypervisorPresent: BOOL,
    // WHV_CAPABILITY_FEATURES
    pub Features: UINT64,
    // WHV_EXTENDED_VM_EXITS
    pub ExtendedVmExits: UINT64,
    pub ProcessorVendor: WHV_PROCESSOR_VENDOR,
    // WHV_PROCESSOR_FEATURES
    pub ProcessorFeatures: UINT64,
    pub ProcessorClFlushSize: UINT8,
    pub ExceptionExitBitmap: UINT64,
}

#[allow(non_snake_case)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WHV_X64_CPUID_RESULT {
    pub Function: UINT32,
    pub Reserved: [UINT32; 3],
    pub Eax: UINT32,
    pub Ebx: UINT32,
    pub Ecx: UINT32,
    pub Edx: UINT32,
}

#[allow(non_snake_case)]
#[repr(C)]
pub union WHV_PARTITION_PROPERTY {
    // WHV_EXTENDED_VM_EXITS
    pub ExtendedVmExits: UINT64,
    // WHV_PROCESSOR_FEATURES
    pub ProcessorFeatures: UINT64,
    pub ProcessorClFlushSize: UINT8,
    pub ProcessorCount: UINT32,
    pub CpuidExitList: [UINT32; 1],
    pub CpuidResultList: [WHV_X64_CPUID_RESULT; 1],
    pub ExceptionExitBitmap: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_SEGMENT_REGISTER {
    pub Base: UINT64,
    pub Limit: UINT32,
    pub Selector: UINT16,
    // Bit fields are not supported in Rust.
    pub Attributes: UINT16,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_TABLE_REGISTER {
    pub Pad: [UINT16; 3],
    pub Limit: UINT16,
    pub Base: UINT64,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_VP_EXIT_CONTEXT {
    // WHV_X64_VP_EXECUTION_STATE
    pub ExecutionState: UINT16,
    // Rust doesn't support bit fields so InstructionLength (4 bits) and Cr8 (4 bits)
    // are combined here
    pub InstructionLengthCr8: UINT8,
    pub Reserved: UINT8,
    pub Reserved2: UINT32,
    pub Cs: WHV_X64_SEGMENT_REGISTER,
    pub Rip: UINT64,
    pub Rflags: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_MEMORY_ACCESS_CONTEXT {
    // Context of the virtual processor
    pub InstructionByteCount: UINT8,
    pub Reserved: [UINT8; 3],
    pub InstructionBytes: [UINT8; 16],

    // Memory access info
    // WHV_MEMORY_ACCESS_INFO
    pub AccessInfo: UINT32,
    pub Gpa: WHV_GUEST_PHYSICAL_ADDRESS,
    pub Gva: WHV_GUEST_VIRTUAL_ADDRESS,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_IO_PORT_ACCESS_CONTEXT {
    // Context of the virtual processor
    pub InstructionByteCount: UINT8,
    pub Reserved: [UINT8; 3],
    pub InstructionBytes: [UINT8; 16],

    // I/O port access info
    // WHV_X64_IO_PORT_ACCESS_INFO
    pub AccessInfo: UINT32,
    pub PortNumber: UINT16,
    pub Reserved2: [UINT16; 3],
    pub Rax: UINT64,
    pub Rcx: UINT64,
    pub Rsi: UINT64,
    pub Rdi: UINT64,
    pub Ds: WHV_X64_SEGMENT_REGISTER,
    pub Es: WHV_X64_SEGMENT_REGISTER,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_MSR_ACCESS_CONTEXT {
    // MSR access info
    // WHV_X64_MSR_ACCESS_INFO
    pub AccessInfo: UINT32,
    pub MsrNumber: UINT32,
    pub Rax: UINT64,
    pub Rdx: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_CPUID_ACCESS_CONTEXT {
    // CPUID access info
    pub Rax: UINT64,
    pub Rcx: UINT64,
    pub Rdx: UINT64,
    pub Rbx: UINT64,
    pub DefaultResultRax: UINT64,
    pub DefaultResultRcx: UINT64,
    pub DefaultResultRdx: UINT64,
    pub DefaultResultRbx: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_VP_EXCEPTION_CONTEXT {
    pub InstructionByteCount: UINT8,
    pub Reserved: [UINT8; 3],
    pub InstructionBytes: [UINT8; 16],

    // Exception info
    // WHV_VP_EXCEPTION_INFO
    pub ExceptionInfo: UINT32,
    // WHV_EXCEPTION_TYPE
    pub ExceptionType: UINT8,
    pub Reserved2: [UINT8; 3],
    pub ErrorCode: UINT32,
    pub ExceptionParameter: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT {
    pub DeliverableType: WHV_X64_PENDING_INTERRUPTION_TYPE,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_X64_UNSUPPORTED_FEATURE_CONTEXT {
    pub FeatureCode: WHV_X64_UNSUPPORTED_FEATURE_CODE,
    pub Reserved: UINT32,
    pub FeatureParameter: UINT64,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_RUN_VP_CANCELED_CONTEXT {
    pub CancelReason: WHV_RUN_VP_CANCEL_REASON,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub union WHV_RUN_VP_EXIT_CONTEXT_anon_union {
    pub MemoryAccess: WHV_MEMORY_ACCESS_CONTEXT,
    pub IoPortAccess: WHV_X64_IO_PORT_ACCESS_CONTEXT,
    pub MsrAccess: WHV_X64_MSR_ACCESS_CONTEXT,
    pub CpuidAccess: WHV_X64_CPUID_ACCESS_CONTEXT,
    pub VpException: WHV_VP_EXCEPTION_CONTEXT,
    pub InterruptWindow: WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT,
    pub UnsupportedFeature: WHV_X64_UNSUPPORTED_FEATURE_CONTEXT,
    pub CancelReason: WHV_RUN_VP_CANCELED_CONTEXT,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_RUN_VP_EXIT_CONTEXT {
    pub ExitReason: WHV_RUN_VP_EXIT_REASON,
    pub Reserved: UINT32,
    pub VpContext: WHV_VP_EXIT_CONTEXT,
    pub anon_union: WHV_RUN_VP_EXIT_CONTEXT_anon_union,
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_UINT128 {
    pub Low64: UINT64,
    pub High64: UINT64,
    // Original type is a union that includes also:
    // UINT32  Dword[4];
}

#[derive(Copy, Clone)]
#[allow(non_snake_case)]
#[repr(C)]
pub union WHV_REGISTER_VALUE {
    pub Reg128: WHV_UINT128,
    pub Reg64: UINT64,
    pub Reg32: UINT32,
    pub Reg16: UINT16,
    pub Reg8: UINT8,
    // WHV_X64_FP_REGISTER
    pub Fp: WHV_UINT128,
    // WHV_X64_FP_CONTROL_STATUS_REGISTER
    pub FpControlStatus: WHV_UINT128,
    // WHV_X64_XMM_CONTROL_STATUS_REGISTER
    pub XmmControlStatus: WHV_UINT128,
    pub Segment: WHV_X64_SEGMENT_REGISTER,
    pub Table: WHV_X64_TABLE_REGISTER,
    // WHV_X64_INTERRUPT_STATE_REGISTER
    pub InterruptState: UINT64,
    // WHV_X64_PENDING_INTERRUPTION_REGISTER
    pub PendingInterruption: UINT64,
    // WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER
    pub DeliverabilityNotifications: UINT64,
}

#[allow(non_snake_case)]
#[repr(C)]
pub struct WHV_TRANSLATE_GVA_RESULT {
    pub ResultCode: WHV_TRANSLATE_GVA_RESULT_CODE,
    pub Reserved: UINT32,
}

#[allow(non_snake_case)]
#[link(name = "WinHvPlatform")]
extern "stdcall" {
    pub fn WHvCreatePartition(Partition: *mut WHV_PARTITION_HANDLE) -> HRESULT;
    pub fn WHvSetupPartition(Partition: WHV_PARTITION_HANDLE) -> HRESULT;
    pub fn WHvDeletePartition(Partition: WHV_PARTITION_HANDLE) -> HRESULT;
    pub fn WHvCreateVirtualProcessor(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        Flags: UINT32,
    ) -> HRESULT;
    pub fn WHvDeleteVirtualProcessor(Partition: WHV_PARTITION_HANDLE, VpIndex: UINT32) -> HRESULT;
    pub fn WHvSetPartitionProperty(
        Partition: WHV_PARTITION_HANDLE,
        PropertyCode: WHV_PARTITION_PROPERTY_CODE,
        PropertyBuffer: *const VOID,
        PropertyBufferSizeInBytes: UINT32,
    ) -> HRESULT;
    pub fn WHvGetPartitionProperty(
        Partition: WHV_PARTITION_HANDLE,
        PropertyCode: WHV_PARTITION_PROPERTY_CODE,
        PropertyBuffer: *mut VOID,
        PropertyBufferSizeInBytes: UINT32,
        WrittenSizeInBytes: *mut UINT32,
    ) -> HRESULT;
    pub fn WHvGetCapability(
        CapabilityCode: WHV_CAPABILITY_CODE,
        CapabilityBuffer: *mut VOID,
        CapabilityBufferSizeInBytes: UINT32,
        WrittenSizeInBytes: *mut UINT32,
    ) -> HRESULT;
    pub fn WHvCancelRunVirtualProcessor(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        Flags: UINT32,
    ) -> HRESULT;
    pub fn WHvRunVirtualProcessor(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        ExitContext: *mut VOID,
        ExitContextSizeInBytes: UINT32,
    ) -> HRESULT;
    pub fn WHvSetVirtualProcessorRegisters(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        RegisterNames: *const WHV_REGISTER_NAME,
        RegisterCount: UINT32,
        RegisterValues: *const WHV_REGISTER_VALUE,
    ) -> HRESULT;
    pub fn WHvGetVirtualProcessorRegisters(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        RegisterNames: *const WHV_REGISTER_NAME,
        RegisterCount: UINT32,
        RegisterValues: *mut WHV_REGISTER_VALUE,
    ) -> HRESULT;
    pub fn WHvMapGpaRange(
        Partition: WHV_PARTITION_HANDLE,
        SourceAddress: *const VOID,
        GuestAddress: WHV_GUEST_PHYSICAL_ADDRESS,
        SizeInBytes: UINT64,
        Flags: WHV_MAP_GPA_RANGE_FLAGS,
    ) -> HRESULT;
    pub fn WHvUnmapGpaRange(
        Partition: WHV_PARTITION_HANDLE,
        GuestAddress: WHV_GUEST_PHYSICAL_ADDRESS,
        SizeInBytes: UINT64,
    ) -> HRESULT;
    pub fn WHvTranslateGva(
        Partition: WHV_PARTITION_HANDLE,
        VpIndex: UINT32,
        Gva: WHV_GUEST_VIRTUAL_ADDRESS,
        TranslateFlags: WHV_TRANSLATE_GVA_FLAGS,
        TranslationResult: *mut WHV_TRANSLATE_GVA_RESULT,
        Gpa: *mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    fn with_partition<F>(action: F)
    where
        F: Fn(WHV_PARTITION_HANDLE),
    {
        let mut part: WHV_PARTITION_HANDLE = std::ptr::null_mut();

        let result = unsafe { WHvCreatePartition(&mut part) };
        assert_eq!(
            result, S_OK,
            "WHvCreatePartition failed with 0x{:X}",
            result
        );

        action(part);

        let result = unsafe { WHvDeletePartition(part) };
        assert_eq!(
            result, S_OK,
            "WHvDeletePartition failed with 0x{:X}",
            result
        );
    }

    fn with_vcpu<F>(part: WHV_PARTITION_HANDLE, action: F)
    where
        F: Fn(UINT32),
    {
        let vp_index = 0;
        let mut prop: WHV_PARTITION_PROPERTY;

        let result = unsafe {
            prop = std::mem::zeroed();
            prop.ProcessorCount = 1;

            WHvSetPartitionProperty(
                part,
                WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
                &mut prop as *mut _ as *mut VOID,
                std::mem::size_of::<WHV_PARTITION_PROPERTY>() as UINT32,
            )
        };
        assert_eq!(
            result, S_OK,
            "WHvSetPartitionProperty failed with 0x{:X}",
            result
        );

        let result = unsafe { WHvSetupPartition(part) };
        assert_eq!(result, S_OK, "WHvSetupPartition failed with 0x{:X}", result);

        let result = unsafe { WHvCreateVirtualProcessor(part, vp_index, 0) };
        assert_eq!(
            result, S_OK,
            "WHvCreateVirtualProcessor failed with 0x{:X}",
            result
        );

        action(vp_index);

        let result = unsafe { WHvDeleteVirtualProcessor(part, vp_index) };
        assert_eq!(
            result, S_OK,
            "WHvDeleteVirtualProcessor failed with 0x{:X}",
            result
        );
    }

    #[test]
    fn test_data_type_sizes() {
        // Make sure all unions and structs have a size that matches the value
        // obtained with a sizeof() in C.
        assert_eq!(std::mem::size_of::<WHV_CAPABILITY>(), 8);
        assert_eq!(std::mem::size_of::<WHV_X64_CPUID_RESULT>(), 32);
        assert_eq!(std::mem::size_of::<WHV_PARTITION_PROPERTY>(), 32);
        assert_eq!(std::mem::size_of::<WHV_X64_SEGMENT_REGISTER>(), 16);
        assert_eq!(std::mem::size_of::<WHV_X64_TABLE_REGISTER>(), 16);
        assert_eq!(std::mem::size_of::<WHV_VP_EXIT_CONTEXT>(), 40);
        assert_eq!(std::mem::size_of::<WHV_MEMORY_ACCESS_CONTEXT>(), 40);
        assert_eq!(std::mem::size_of::<WHV_X64_IO_PORT_ACCESS_CONTEXT>(), 96);
        assert_eq!(std::mem::size_of::<WHV_X64_MSR_ACCESS_CONTEXT>(), 24);
        assert_eq!(std::mem::size_of::<WHV_X64_CPUID_ACCESS_CONTEXT>(), 64);
        assert_eq!(std::mem::size_of::<WHV_VP_EXCEPTION_CONTEXT>(), 40);
        assert_eq!(
            std::mem::size_of::<WHV_X64_INTERRUPTION_DELIVERABLE_CONTEXT>(),
            4
        );
        assert_eq!(
            std::mem::size_of::<WHV_X64_UNSUPPORTED_FEATURE_CONTEXT>(),
            16
        );
        assert_eq!(std::mem::size_of::<WHV_RUN_VP_CANCELED_CONTEXT>(), 4);
        assert_eq!(std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>(), 144);
        assert_eq!(std::mem::size_of::<WHV_UINT128>(), 16);
        assert_eq!(std::mem::size_of::<WHV_REGISTER_VALUE>(), 16);
        assert_eq!(std::mem::size_of::<WHV_TRANSLATE_GVA_RESULT>(), 8);
    }

    #[test]
    fn test_get_capability() {
        let mut capability: WHV_CAPABILITY;
        let mut written_size: UINT32 = 0;

        let result = unsafe {
            capability = std::mem::zeroed();

            WHvGetCapability(
                WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent,
                &mut capability as *mut _ as *mut VOID,
                std::mem::size_of::<WHV_CAPABILITY>() as UINT32,
                &mut written_size,
            )
        };

        assert_eq!(result, S_OK, "WHvGetCapability failed with 0x{:X}", result);
        assert_eq!(
            std::mem::size_of::<BOOL>() as UINT32,
            written_size,
            "WrittenSizeInBytes does not match BOOL size {}",
            written_size
        );
    }

    #[test]
    fn test_create_delete_partition() {
        with_partition(|_part| {});
    }

    #[test]
    fn test_set_get_partition_property() {
        with_partition(|part| {
            let mut prop: WHV_PARTITION_PROPERTY;
            let mut prop_out: WHV_PARTITION_PROPERTY;
            let mut written_size: UINT32 = 0;

            let result = unsafe {
                prop = std::mem::zeroed();
                prop.ProcessorCount = 1;

                WHvSetPartitionProperty(
                    part,
                    WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
                    &prop as *const _ as *const VOID,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as UINT32,
                )
            };

            assert_eq!(
                result, S_OK,
                "WHvSetPartitionProperty failed with 0x{:X}",
                result
            );

            let result = unsafe {
                prop_out = std::mem::zeroed();

                WHvGetPartitionProperty(
                    part,
                    WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
                    &mut prop_out as *mut _ as *mut VOID,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as UINT32,
                    &mut written_size,
                )
            };

            unsafe {
                assert_eq!(
                    prop.ProcessorCount, prop_out.ProcessorCount,
                    "Partition property value not matching"
                );
            }

            assert_eq!(
                result, S_OK,
                "WHvGetPartitionProperty failed with 0x{:X}",
                result
            );
            assert_eq!(
                std::mem::size_of::<BOOL>() as UINT32,
                written_size,
                "WrittenSizeInBytes does not match BOOL size {}",
                written_size
            );
        });
    }

    #[test]
    fn test_setup_partition() {
        with_partition(|part| {
            let result = unsafe { WHvSetupPartition(part) };
            assert_eq!(
                result, WHV_E_INVALID_PARTITION_CONFIG,
                "WHvSetupPartition failed with 0x{:X}",
                result
            );
        });
    }

    #[test]
    fn test_create_delete_vcpu() {
        with_partition(|part| {
            with_vcpu(part, |_vp_index| {});
        });
    }

    #[test]
    fn test_set_get_vcpu_registers() {
        with_partition(|part| {
            with_vcpu(part, |vp_index| {
                const NUM_REGS: UINT32 = 1;
                const REG_VALUE: UINT64 = 11111111;
                let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize];
                let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize];
                let mut reg_values_out: [WHV_REGISTER_VALUE; NUM_REGS as usize];

                unsafe {
                    reg_names = std::mem::zeroed();
                    reg_values = std::mem::zeroed();
                    reg_values_out = std::mem::zeroed();
                }

                reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRax;
                reg_values[0].Reg64 = REG_VALUE;

                let result = unsafe {
                    WHvSetVirtualProcessorRegisters(
                        part,
                        vp_index,
                        reg_names.as_ptr(),
                        NUM_REGS,
                        reg_values.as_ptr(),
                    )
                };
                assert_eq!(
                    result, S_OK,
                    "WHvSetVirtualProcessorRegisters failed with 0x{:X}",
                    result
                );

                let result = unsafe {
                    WHvGetVirtualProcessorRegisters(
                        part,
                        vp_index,
                        reg_names.as_ptr(),
                        NUM_REGS,
                        reg_values_out.as_mut_ptr(),
                    )
                };
                assert_eq!(
                    result, S_OK,
                    "WHvGetVirtualProcessorRegisters failed with 0x{:X}",
                    result
                );

                unsafe {
                    assert_eq!(
                        reg_values_out[0].Reg64, REG_VALUE,
                        "Registers values fo not match"
                    );
                }
            });
        });
    }

    #[test]
    fn test_run_vcpu() {
        with_partition(|part| {
            with_vcpu(part, |vp_index| {
                let mut exit_context: WHV_RUN_VP_EXIT_CONTEXT;
                let exit_context_size = std::mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as UINT32;

                let result = unsafe {
                    exit_context = std::mem::zeroed();
                    WHvRunVirtualProcessor(
                        part,
                        vp_index,
                        &mut exit_context as *mut _ as *mut VOID,
                        1,
                    )
                };

                assert_eq!(
                    result, WHV_E_INSUFFICIENT_BUFFER,
                    "WHvRunVirtualProcessor failed with 0x{:X}",
                    result
                );

                let result = unsafe {
                    exit_context = std::mem::zeroed();
                    WHvRunVirtualProcessor(
                        part,
                        vp_index,
                        &mut exit_context as *mut _ as *mut VOID,
                        exit_context_size,
                    )
                };

                assert_eq!(
                    result, S_OK,
                    "WHvRunVirtualProcessor failed with 0x{:X}",
                    result
                );

                assert_eq!(
                    exit_context.ExitReason,
                    WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess,
                    "Unexpected exit reason"
                )
            });
        });
    }

    #[test]
    fn test_cancel_run_vcpu() {
        with_partition(|part| {
            with_vcpu(part, |vp_index| {
                let result = unsafe { WHvCancelRunVirtualProcessor(part, vp_index, 0) };

                assert_eq!(
                    result, S_OK,
                    "WHvCancelRunVirtualProcessor failed with 0x{:X}",
                    result
                );
            });
        });
    }

    #[test]
    fn test_map_gpa_range() {
        with_partition(|part| {
            const SIZE: UINT64 = 1024;
            let source_address = Box::new([0; SIZE as usize]);
            let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

            let result = unsafe {
                WHvMapGpaRange(
                    part,
                    source_address.as_ptr() as *const VOID,
                    guest_address,
                    SIZE,
                    WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead,
                )
            };

            // TODO(alexpilotti): modify this test to have an S_OK result.
            // This error is expected with this test setup
            assert_eq!(
                result, E_INVALIDARG,
                "WHvMapGpaRange failed with 0x{:X}",
                result
            );
        });
    }

    #[test]
    fn test_unmap_gpa_range_not_found() {
        with_partition(|part| {
            const SIZE: UINT64 = 1024;
            let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

            let result = unsafe { WHvUnmapGpaRange(part, guest_address, SIZE) };

            assert_eq!(
                result, WHV_E_GPA_RANGE_NOT_FOUND,
                "WHvUnmapGpaRange failed with 0x{:X}",
                result
            );
        });
    }

    #[test]
    fn test_translate_gva() {
        with_partition(|part| {
            with_vcpu(part, |vp_index| {
                let gva: WHV_GUEST_PHYSICAL_ADDRESS = 0;
                let mut gpa: WHV_GUEST_PHYSICAL_ADDRESS = 0;
                let mut translation_result: WHV_TRANSLATE_GVA_RESULT;

                let result = unsafe {
                    translation_result = std::mem::zeroed();
                    WHvTranslateGva(
                        part,
                        vp_index,
                        gva,
                        WHV_TRANSLATE_GVA_FLAGS::WHvTranslateGvaFlagValidateRead,
                        &mut translation_result,
                        &mut gpa,
                    )
                };

                assert_eq!(result, S_OK, "WHvTranslateGva failed with 0x{:X}", result);

                assert_eq!(
                    translation_result.ResultCode,
                    WHV_TRANSLATE_GVA_RESULT_CODE::WHvTranslateGvaResultGpaUnmapped,
                    "Unexpected translation result code {:?}",
                    translation_result.ResultCode
                );

                assert_eq!(gpa, 0, "Unexpected GPA value");
            });
        });
    }
}
