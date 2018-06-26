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

use common_defs::*;

pub type WHV_PARTITION_HANDLE = *mut VOID;

pub type WHV_GUEST_PHYSICAL_ADDRESS = UINT64;
pub type WHV_GUEST_VIRTUAL_ADDRESS = UINT64;

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
