// Copyright 2018 Cloudbase Solutions Srl
// Copyright 2018-2019 CrowdStrike, Inc.
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
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const INT_VECTOR: u32 = 0x35;

#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
struct CpuInfo {
    apic_enabled: bool,
}

fn main() {
    check_hypervisor();

    let mut p = Partition::new().unwrap();

    let apic_present = is_apic_present();

    let mut cpu_info = CpuInfo {
        apic_enabled: false,
    };

    setup_partition(&mut p, &mut cpu_info, apic_present);

    let mem_size = 0x300000;
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

    let mut e = Emulator::<SampleCallbacks>::new().unwrap();

    if cpu_info.apic_enabled {
        // Set the APIC base and send an interrupt to the VCPU
        set_apic_base(&mut vp_ref_cell.borrow_mut());
        send_ipi(&mut vp_ref_cell.borrow_mut(), INT_VECTOR);
        set_delivery_notifications(&mut vp_ref_cell.borrow_mut());
    }

    loop {
        let exit_context = vp_ref_cell.borrow_mut().run().unwrap();

        match exit_context.ExitReason {
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => {
                println!("All done!");
                break;
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => {
                break;
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                handle_mmio_exit(&mut e, &mut callbacks, &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                handle_io_port_exit(&mut e, &mut callbacks, &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                handle_cpuid_exit(&mut vp_ref_cell.borrow_mut(), &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                handle_msr_exit(&mut vp_ref_cell.borrow_mut(), &exit_context)
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => {
                println!("ApicEoi");
            }
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                println!("Interrupt window");
            }
            _ => panic!("Unexpected exit type: {:?}", exit_context.ExitReason),
        };

        // With the APIC enabled, the hlt instruction will not completely halt
        // the processor; it'll just halt it until another interrupt is
        // received, so we don't receive the VMexit that we used to use to end
        // VCPU execution. Since WHV will not let us disable the APIC in the usual
        // means (eg, via the global enable flag of the APIC_BASE register,
        // etc), teriminate the VCPU execution loop when both interrupts we're
        // expecting have been received. Plus we get to exercise the new
        // counter APIs.
        if all_interrupts_received(&vp_ref_cell.borrow()) {
            println!("All interrupts received. All done!");
            break;
        }
    }
}

/*
 * Terminate VCPU execution when two interrupts have been received by the guest:
 * one from the host, and one from the guest
 */
fn all_interrupts_received(vp: &VirtualProcessor) -> bool {
    let counters: WHV_PROCESSOR_COUNTERS = vp
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetApic)
        .unwrap();
    let apic_counters = unsafe { counters.ApicCounters };

    if apic_counters.EoiAccessCount == 2 {
        true
    } else {
        false
    }
}

fn set_apic_base(vp: &mut VirtualProcessor) {
    // Page table translations for this guest only cover the first 1GB of memory,
    // and the default APIC base falls above that. Set the APIC base to
    // something lower, within our range of virtual memory

    // Get the default APIC base register value to start
    const NUM_REGS: usize = 1;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;

    // Get the registers as a baseline
    vp.get_registers(&reg_names, &mut reg_values).unwrap();
    let mut flags = unsafe { reg_values[0].Reg64 };

    // Mask off the bottom 12 bits, which are used to store flags
    flags = flags & 0xfff;

    // Set the APIC base to something lower within our translatable address
    // space
    let new_apic_base = 0x0fee_0000;
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;
    reg_values[0].Reg64 = new_apic_base | flags;
    vp.set_registers(&reg_names, &reg_values).unwrap();
}

fn send_msi(vp: &mut VirtualProcessor, message: &WHV_MSI_ENTRY) {
    let addr: UINT32 = unsafe { message.anon_struct.Address };
    let data: UINT32 = unsafe { message.anon_struct.Data };

    let dest = (addr & MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
    let vector = (data & MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
    let dest_mode = (addr >> MSI_ADDR_DEST_MODE_SHIFT) & 0x1;
    let trigger_mode = (data >> MSI_DATA_TRIGGER_SHIFT) & 0x1;
    let delivery = (data >> MSI_DATA_DELIVERY_MODE_SHIFT) & 0x7;

    let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

    interrupt.set_InterruptType(delivery as UINT64);

    if dest_mode == 0 {
        interrupt.set_DestinationMode(
            WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical as UINT64,
        );
    } else {
        interrupt.set_DestinationMode(
            WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModeLogical as UINT64,
        );
    }

    interrupt.set_TriggerMode(trigger_mode as UINT64);

    interrupt.Destination = dest;
    interrupt.Vector = vector;

    vp.request_interrupt(&mut interrupt).unwrap();
}

fn send_ipi(vp: &mut VirtualProcessor, vector: u32) {
    println!("Send IPI from the host to the guest");

    let mut message: WHV_MSI_ENTRY = Default::default();

    // - Trigger mode is 'Edge'
    // - Interrupt type is 'Fixed'
    // - Destination mode is 'Physical'
    // - Destination is 0. Since Destination Mode is Physical, bits 56-59
    //   contain the APIC ID of the target processor (APIC ID = 0)
    // Level = 1 and Destination Shorthand = 1, but the underlying API will
    // actually ignore this.
    unsafe {
        message.anon_struct.Data = (0x00044000 | vector) as UINT32;
        message.anon_struct.Address = 0;
    }

    send_msi(vp, &message);
}

fn set_delivery_notifications(vp: &mut VirtualProcessor) {
    const NUM_REGS: usize = 1;
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();

    let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER = Default::default();
    notifications.set_InterruptNotification(1);
    reg_values[0].DeliverabilityNotifications = notifications;
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications;
    vp.set_registers(&reg_names, &reg_values).unwrap();
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
            println!("Unknown MSR number: {:#x}", msr_access.MsrNumber);
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
    context: &mut T,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let mem_access_ctx = unsafe { &exit_context.anon_union.MemoryAccess };
    let _status = e
        .try_mmio_emulation(
            context,
            &exit_context.VpContext,
            mem_access_ctx,
        )
        .unwrap();
}

fn handle_io_port_exit<T: EmulatorCallbacks>(
    e: &mut Emulator<T>,
    context: &mut T,
    exit_context: &WHV_RUN_VP_EXIT_CONTEXT,
) {
    let io_port_access_ctx = unsafe { &exit_context.anon_union.IoPortAccess };
    let _status = e
        .try_io_emulation(
            context,
            &exit_context.VpContext,
            io_port_access_ctx,
        )
        .unwrap();
}

fn setup_partition(p: &mut Partition, cpu_info: &mut CpuInfo, apic_present: bool) {
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

    if apic_present != false {
        enable_apic(p, cpu_info);
    }

    p.setup().unwrap();
}

fn is_apic_present() -> bool {
    let capability: WHV_CAPABILITY =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
    let features: WHV_CAPABILITY_FEATURES = unsafe { capability.Features };

    if features.LocalApicEmulation() != 0 {
        true
    } else {
        false
    }
}

fn enable_apic(p: &mut Partition, cpu_info: &mut CpuInfo) {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();
    property.LocalApicEmulationMode =
        WHV_X64_LOCAL_APIC_EMULATION_MODE::WHvX64LocalApicEmulationModeXApic;

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeLocalApicEmulationMode,
        &property,
    )
    .unwrap();

    cpu_info.apic_enabled = true;
}

fn initialize_address_space(payload_mem: &VirtualMemory) -> u64 {
    let mem_addr = payload_mem.as_ptr() as u64;

    let pml4_addr: u64 = 0x9000;
    let pdpt_addr: u64 = 0xa000;
    let pd_addr: u64 = 0xb000;
    let pml4: u64 = mem_addr + pml4_addr;
    let pdpt: u64 = mem_addr + pdpt_addr;
    let pd: u64 = mem_addr + pd_addr;

    unsafe {
        *(pml4 as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
        *(pdpt as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

        for i in 0..512 {
            *((pd + i * 8) as *mut u64) =
                (i << 21) + (PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS);
        }
    }

    // Return the PML4 guest physical address so the caller can use it to set CR3
    pml4_addr
}

fn setup_long_mode(vp: &mut VirtualProcessor, payload_mem: &VirtualMemory) {
    let pml4_addr = initialize_address_space(payload_mem);

    const NUM_REGS: UINT32 = 13;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = Default::default();
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = Default::default();

    // Setup paging
    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
    reg_values[0].Reg64 = pml4_addr;
    reg_names[1] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
    reg_values[1].Reg64 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;

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

    // Start with the Interrupt Flag off; guest will enable it when ready
    reg_names[10] = WHV_REGISTER_NAME::WHvX64RegisterRflags;
    reg_values[10].Reg64 = 0x002;

    reg_names[11] = WHV_REGISTER_NAME::WHvX64RegisterRip;
    reg_values[11].Reg64 = 0;

    // Create stack with stack base at high end of mapped payload
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
        io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {
        if io_access.Direction == 1 {
            // Our payload writes to port 42
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
        }
        else {
            // Our payload reads from port 43. Set a value in the Data buffer
            // to simulate an IO read, that the payload will "read" later
            if io_access.Port == 43 {
                let data = unsafe {
                    std::slice::from_raw_parts_mut(
                        &mut io_access.Data as *mut _ as *mut u8,
                        io_access.AccessSize as usize,
                    )
                };
                data[0] = 99;
            }
        }
        S_OK
    }

    fn memory(
        &mut self,
        memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {
        let addr = memory_access.GpaAddress;
        match memory_access.AccessSize {
            8 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u64;
                    unsafe {
                        *data = 0x1000;
                        println!("MMIO read: 0x{:016x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u64) };
                    println!("MMIO write: 0x{:016x} @0x{:x}", value, addr);
                }
            },
            4 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x1000;
                        println!("MMIO read: 0x{:08x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    println!("MMIO write: 0x{:08x} @0x{:x}", value, addr);
                }
            },
            2 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x22bb;
                        println!("MMIO read: 0x{:04x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    println!("MMIO write: 0x{:04x} @0x{:x}", value, addr);
                }
            },
            1 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x58;
                        println!("MMIO read: 0x{:02x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    println!("MMIO write: 0x{:02x} @0x{:x}", value, addr);
                }
            },
            _ => println!("Unsupported MMIO access size: {}", memory_access.AccessSize),
        }

        S_OK
    }

    fn get_virtual_processor_registers(
        &mut self,
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
