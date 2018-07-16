# libwhp

Windows Hypervisor Platform API for Rust:
https://docs.microsoft.com/en-us/virtualization/api/

This crate takes advantage of the safety, lifetime, memory management and
error handling features available in Rust while retaining the original design
of the native Windows Hypervisor Platform (WHP) API.

```
extern crate libwhp;

use libwhp::*;

fn main() {
    let mut p = Partition::new().unwrap();

    let mut property: WHV_PARTITION_PROPERTY = unsafe { std::mem::zeroed() };
    property.ProcessorCount = 1;
    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
        &property,
    ).unwrap();

    p.setup().unwrap();

    // Replace with an actual mapping
    const SIZE: UINT64 = 1024;
    let source_address = Box::new([0; SIZE as usize]);
    let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

    p.map_gpa_range(
        source_address.as_ptr() as *const VOID,
        guest_address,
        SIZE,
        WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead,
    ).unwrap();

    let mut vp = p.create_virtual_processor(0).unwrap();

    // Replace with actual register values
    const NUM_REGS: UINT32 = 1;
    let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS as usize] = unsafe { std::mem::zeroed() };
    let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS as usize] = unsafe { std::mem::zeroed() };

    reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterRax;
    reg_values[0].Reg64 = 0;

    vp.set_registers(&reg_names, &reg_values).unwrap();

    loop {
        let exit_context = vp.run().unwrap();
        // Handle exits
        if exit_context.ExitReason == WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt {
            break;
        }
    }

    // To translate a GVA into a GPA:
    let gva: WHV_GUEST_PHYSICAL_ADDRESS = 0;
    let (_translation_result, _gpa) = vp.translate_gva(
        gva,
        WHV_TRANSLATE_GVA_FLAGS::WHvTranslateGvaFlagValidateRead,
    ).unwrap();
}
```
