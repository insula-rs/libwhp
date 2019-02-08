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

extern crate libc;
extern crate libwhp;

use libwhp::instruction_emulator::*;
use libwhp::memory::*;
use libwhp::*;

use std::cell::RefCell;
use std::fs::File;
use std::io::prelude::*;
use std::io::{self, Write};
use std::path::PathBuf;

const CPUID_EXT_HYPERVISOR: UINT32 = 1 << 31;

const PDE64_PRESENT: u64 = 1;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const PDE64_PS: u64 = 1 << 7;
const CR4_PAE: u64 = 1 << 5;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

fn main() {
    check_hypervisor();

    let mut p = Partition::new().unwrap();
    setup_partition(&mut p);

    let mem_size = 0x100000;
    let mut payload_mem = VirtualMemory::new(mem_size).unwrap();

    let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

    let _mapping = p
        .map_gpa_range(
            &payload_mem,
            guest_address,
            payload_mem.get_size() as UINT64,
            WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagExecute,
        )
        .unwrap();

    let mut vp = p.create_virtual_processor(0).unwrap();

    setup_long_mode(&mut vp, &payload_mem);
    read_payload(&mut payload_mem);

    let vp_ref_cell = RefCell::new(vp);

    let mut callbacks = SampleCallbacks {
        vp_ref_cell: &vp_ref_cell,
    };
    let mut e = Emulator::new(&mut callbacks).unwrap();

    loop {
        let exit_context = vp_ref_cell.borrow_mut().run().unwrap();
        match exit_context.ExitReason {
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => {
                println!("All done!");
                break;
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                handle_mmio_exit(&mut e, &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                handle_io_port_exit(&mut e, &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                handle_cpuid_exit(&mut vp_ref_cell.borrow_mut(), &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                handle_msr_exit(&mut vp_ref_cell.borrow_mut(), &exit_context)
            }
            _ => panic!("Unexpected exit type: {:?}", exit_context.ExitReason),
        };
    }
}

fn handle_msr_exit(vp: &mut VirtualProcessor, exit_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    let msr_access = unsafe { exit_context.anon_union.MsrAccess };

    const NUM_REGS: UINT32 = 3;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterRax;
    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterRdx;

    reg_values[0].Reg64 =
        exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;

    match msr_access.MsrNumber {
        1 => {
            if msr_access.AccessInfo.IsWrite() == 1 {
                println!(
                    "MSR write. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, msr_access.Rax, msr_access.Rdx
                );
            } else {
                let rax = 0x2000;
                let rdx = 0x2001;
                reg_values[1].Reg64 = rax;
                reg_values[2].Reg64 = rdx;
                println!(
                    "MSR read. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, rax, rdx
                );
            }
        }
        _ => {
            println!("Unknown MSR number: {}", msr_access.MsrNumber);
        }
    }

    let mut num_regs_set = NUM_REGS as usize;
    if msr_access.AccessInfo.IsWrite() == 1 {
        num_regs_set = 1;
    }

    vp.set_registers(&reg_names[0..num_regs_set], &reg_values[0..num_regs_set])
        .unwrap();
}

fn handle_cpuid_exit(vp: &mut VirtualProcessor, exit_context: &WHV_RUN_VP_EXIT_CONTEXT) {
    let cpuid_access = unsafe { exit_context.anon_union.CpuidAccess };
    println!("Got CPUID leaf: {}", cpuid_access.Rax);

    const NUM_REGS: UINT32 = 5;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterRax;
    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterRbx;
    reg_names[3] = WHV_REGISTER_NAME::WHvX64RegisterRcx;
    reg_names[4] = WHV_REGISTER_NAME::WHvX64RegisterRdx;

    reg_values[0].Reg64 =
        exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;
    reg_values[1].Reg64 = cpuid_access.DefaultResultRax;
    reg_values[2].Reg64 = cpuid_access.DefaultResultRbx;
    reg_values[3].Reg64 = cpuid_access.DefaultResultRcx;
    reg_values[4].Reg64 = cpuid_access.DefaultResultRdx;

    match cpuid_access.Rax {
        1 => {
            reg_values[3].Reg64 = CPUID_EXT_HYPERVISOR as UINT64;
        }
        _ => {
            println!("Unknown CPUID leaf: {}", cpuid_access.Rax);
        }
    }

    vp.set_registers(&reg_names, &reg_values).unwrap();
}

fn handle_mmio_exit<T: EmulatorCallbacks>(
    e: &mut Emulator<T>,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let mem_access_ctx = unsafe { &exit_context.anon_union.MemoryAccess };
    let _status = e
        .try_mmio_emulation(
            std::ptr::null_mut(),
            &exit_context.VpContext,
            mem_access_ctx,
        )
        .unwrap();
}

fn handle_io_port_exit<T: EmulatorCallbacks>(
    e: &mut Emulator<T>,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let io_port_access_ctx = unsafe { &exit_context.anon_union.IoPortAccess };
    let _status = e
        .try_io_emulation(
            std::ptr::null_mut(),
            &exit_context.VpContext,
            io_port_access_ctx,
        )
        .unwrap();
}

fn setup_partition(p: &mut Partition) {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();
    property.ProcessorCount = 1;
    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
        &property,
    )
    .unwrap();

    property = Default::default();
    unsafe {
        property.ExtendedVmExits.set_X64CpuidExit(1);
        property.ExtendedVmExits.set_X64MsrExit(1);
        property.ExtendedVmExits.set_ExceptionExit(1);
    }

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeExtendedVmExits,
        &property,
    )
    .unwrap();

    let cpuids: [UINT32; 1] = [1];
    p.set_property_cpuid_exits(&cpuids).unwrap();

    let mut cpuid_results: [WHV_X64_CPUID_RESULT; 1] = Default::default();

    cpuid_results[0].Function = 0x40000000;
    let mut id_reg_values: [UINT32; 3] = [0; 3];
    let id = "libwhp\0";
    unsafe {
        std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
    }
    cpuid_results[0].Ebx = id_reg_values[0];
    cpuid_results[0].Ecx = id_reg_values[1];
    cpuid_results[0].Edx = id_reg_values[2];

    p.set_property_cpuid_results(&cpuid_results).unwrap();

    p.setup().unwrap();
}

fn setup_long_mode(vp: &mut VirtualProcessor, payload_mem: &VirtualMemory) {
    let mem_addr = payload_mem.as_ptr() as u64;

    let pml4_addr: u64 = 0x2000;
    let pdpt_addr: u64 = 0x3000;
    let pd_addr: u64 = 0x4000;
    let pml4: u64 = mem_addr + pml4_addr;
    let pdpt: u64 = mem_addr + pdpt_addr;
    let pd: u64 = mem_addr + pd_addr;

    unsafe {
        *(pml4 as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
        *(pdpt as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
        *(pd as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
    }

    const NUM_REGS: UINT32 = 13;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    // Setup paging
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
    reg_values[0].Reg64 = pml4_addr;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
    reg_values[1].Reg64 = CR4_PAE;
    reg_names[2] = WHV_REGISTER_NAME::WHvX64RegisterCr0;
    reg_values[2].Reg64 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    reg_names[3] = WHV_REGISTER_NAME::WHvX64RegisterEfer;
    reg_values[3].Reg64 = EFER_LME | EFER_LMA;

    reg_names[4] = WHV_REGISTER_NAME::WHvX64RegisterCs;
    unsafe {
        let segment = &mut reg_values[4].Segment;
        segment.Base = 0;
        segment.Limit = 0xffffffff;
        segment.Selector = 1 << 3;
        segment.set_SegmentType(11);
        segment.set_NonSystemSegment(1);
        segment.set_Present(1);
        segment.set_Long(1);
        segment.set_Granularity(1);
    }

    reg_names[5] = WHV_REGISTER_NAME::WHvX64RegisterDs;
    unsafe {
        let segment = &mut reg_values[5].Segment;
        segment.Base = 0;
        segment.Limit = 0xffffffff;
        segment.Selector = 2 << 3;
        segment.set_SegmentType(3);
        segment.set_NonSystemSegment(1);
        segment.set_Present(1);
        segment.set_Long(1);
        segment.set_Granularity(1);
    }

    reg_names[6] = WHV_REGISTER_NAME::WHvX64RegisterEs;
    reg_values[6] = reg_values[5];

    reg_names[7] = WHV_REGISTER_NAME::WHvX64RegisterFs;
    reg_values[7] = reg_values[5];

    reg_names[8] = WHV_REGISTER_NAME::WHvX64RegisterGs;
    reg_values[8] = reg_values[5];

    reg_names[9] = WHV_REGISTER_NAME::WHvX64RegisterSs;
    reg_values[9] = reg_values[5];

    reg_names[10] = WHV_REGISTER_NAME::WHvX64RegisterRflags;
    reg_values[10].Reg64 = 2;
    reg_names[11] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_values[11].Reg64 = 0;
    // Create stack
    reg_names[12] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
    reg_values[12].Reg64 = payload_mem.get_size() as UINT64;

    vp.set_registers(&reg_names, &reg_values).unwrap();
}

fn read_payload(mem_addr: &mut VirtualMemory) {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("examples");
    p.push("payload");
    p.push("payload.img");

    let mut f = File::open(&p).expect(&format!(
        "Cannot find \"{}\". Run \"make\" in the same folder to build it",
        &p.to_str().unwrap()
    ));
    f.read(mem_addr.as_slice_mut()).unwrap();
}

fn check_hypervisor() {
    let capability =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent).unwrap();
    if unsafe { capability.HypervisorPresent } == FALSE {
        panic!("Hypervisor not present");
    }
}

struct SampleCallbacks<'a> {
    vp_ref_cell: &'a RefCell<VirtualProcessor>,
}

impl<'a> EmulatorCallbacks for SampleCallbacks<'a> {
    fn io_port(
        &mut self,
        _context: *mut VOID,
        io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {
        if io_access.Port == 42 {
            let data = unsafe {
                std::slice::from_raw_parts(
                    &io_access.Data as *const _ as *const u8,
                    io_access.AccessSize as usize,
                )
            };
            io::stdout().write(data).unwrap();
        } else {
            println!("Unsupported IO port");
        }
        S_OK
    }

    fn memory(
        &mut self,
        _context: *mut VOID,
        memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {
        match memory_access.AccessSize {
            8 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u64;
                    unsafe {
                        *data = 0x1000;
                        println!("MMIO read: 0x{:x}", *data);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u64) };
                    println!("MMIO write: 0x{:x}", value);
                }
            },
            _ => println!("Unsupported MMIO access size: {}", memory_access.AccessSize),
        }
        S_OK
    }

    fn get_virtual_processor_registers(
        &mut self,
        _context: *mut VOID,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vp_ref_cell
            .borrow()
            .get_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn set_virtual_processor_registers(
        &mut self,
        _context: *mut VOID,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &[WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vp_ref_cell
            .borrow_mut()
            .set_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn translate_gva_page(
        &mut self,
        _context: *mut VOID,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        let (translation_result1, gpa1) = self
            .vp_ref_cell
            .borrow()
            .translate_gva(gva, translate_flags)
            .unwrap();
        *translation_result = translation_result1.ResultCode;
        *gpa = gpa1;
        S_OK
    }
}
