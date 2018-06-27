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

use common_defs::*;
use std;
use win_hv_emulation::*;
use win_hv_emulation_defs::*;
use win_hv_platform_defs::*;

pub trait EmulatorCallbacks {
    fn io_port(
        &mut self,
        context: *const VOID,
        io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT;
    fn memory(
        &mut self,
        context: *const VOID,
        memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT;
    fn get_virtual_processor_registers(
        &mut self,
        context: *const VOID,
        register_names: &[WHV_REGISTER_NAME],
        reg_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT;
    fn set_virtual_processor_registers(
        &mut self,
        context: *const VOID,
        register_names: &[WHV_REGISTER_NAME],
        reg_values: &[WHV_REGISTER_VALUE],
    ) -> HRESULT;
    fn translate_gva_page(
        &mut self,
        context: *const VOID,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT;
}

struct CallbacksContext<'a, T: EmulatorCallbacks + 'a> {
    callbacks: &'a mut T,
    context: *mut VOID,
}

pub struct Emulator<'a, T: EmulatorCallbacks + 'a> {
    emulator: WHV_EMULATOR_HANDLE,
    callbacks: &'a mut T,
}

impl<'a, T: 'a> Emulator<'a, T>
where
    T: EmulatorCallbacks,
{
    pub fn new(callbacks: &mut T) -> Result<Emulator<T>, HRESULT> {
        let mut emulator: WHV_EMULATOR_HANDLE = std::ptr::null_mut();

        let native_callbacks = WHV_EMULATOR_CALLBACKS {
            Size: std::mem::size_of::<WHV_EMULATOR_CALLBACKS>() as UINT32,
            Reserved: 0,
            WHvEmulatorIoPortCallback: Emulator::<T>::io_port_cb,
            WHvEmulatorMemoryCallback: Emulator::<T>::memory_cb,
            WHvEmulatorGetVirtualProcessorRegisters: Emulator::<T>::get_vp_registers_cb,
            WHvEmulatorSetVirtualProcessorRegisters: Emulator::<T>::set_vp_registers_cb,
            WHvEmulatorTranslateGvaPage: Emulator::<T>::translate_gva_page_cb,
        };

        check_result(unsafe { WHvEmulatorCreateEmulator(&native_callbacks, &mut emulator) })?;
        Ok(Emulator {
            emulator: emulator,
            callbacks: callbacks,
        })
    }

    extern "stdcall" fn io_port_cb(
        context: *mut VOID,
        io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {
        let cc = unsafe { &mut *(context as *mut CallbacksContext<T>) };
        cc.callbacks.io_port(cc.context, unsafe { &mut *io_access })
    }

    extern "stdcall" fn memory_cb(
        context: *mut VOID,
        memory_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {
        let cc = unsafe { &mut *(context as *mut CallbacksContext<T>) };
        cc.callbacks
            .memory(cc.context, unsafe { &mut *memory_access })
    }

    extern "stdcall" fn get_vp_registers_cb(
        context: *mut VOID,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *mut WHV_REGISTER_VALUE,
    ) -> HRESULT {
        let cc = unsafe { &mut *(context as *mut CallbacksContext<T>) };
        cc.callbacks.get_virtual_processor_registers(
            cc.context,
            unsafe { std::slice::from_raw_parts(register_names, register_count as usize) },
            unsafe { std::slice::from_raw_parts_mut(register_values, register_count as usize) },
        )
    }

    extern "stdcall" fn set_vp_registers_cb(
        context: *mut VOID,
        register_names: *const WHV_REGISTER_NAME,
        register_count: UINT32,
        register_values: *const WHV_REGISTER_VALUE,
    ) -> HRESULT {
        let cc = unsafe { &mut *(context as *mut CallbacksContext<T>) };

        cc.callbacks.set_virtual_processor_registers(
            cc.context,
            unsafe { std::slice::from_raw_parts(register_names, register_count as usize) },
            unsafe { std::slice::from_raw_parts(register_values, register_count as usize) },
        )
    }

    extern "stdcall" fn translate_gva_page_cb(
        context: *mut VOID,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: *mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        let cc = unsafe { &mut *(context as *mut CallbacksContext<T>) };
        cc.callbacks.translate_gva_page(
            cc.context,
            gva,
            translate_flags,
            unsafe { &mut *translation_result },
            unsafe { &mut *gpa },
        )
    }

    pub fn try_io_emulation(
        &mut self,
        context: *mut VOID,
        vp_context: &WHV_VP_EXIT_CONTEXT,
        io_instruction_context: &mut WHV_X64_IO_PORT_ACCESS_CONTEXT,
    ) -> Result<WHV_EMULATOR_STATUS, HRESULT> {
        let mut callbacks_context = CallbacksContext {
            callbacks: self.callbacks,
            context: context,
        };

        let mut return_status: WHV_EMULATOR_STATUS = 0;
        check_result(unsafe {
            WHvEmulatorTryIoEmulation(
                self.emulator,
                &mut callbacks_context as *mut _ as *mut VOID,
                vp_context,
                io_instruction_context,
                &mut return_status,
            )
        })?;
        Ok(return_status)
    }

    pub fn try_mmio_emulation(
        &mut self,
        context: *mut VOID,
        vp_context: &WHV_VP_EXIT_CONTEXT,
        mmio_instruction_context: &WHV_MEMORY_ACCESS_CONTEXT,
    ) -> Result<WHV_EMULATOR_STATUS, HRESULT> {
        let mut callbacks_context = CallbacksContext {
            callbacks: self.callbacks,
            context: context,
        };

        let mut return_status: WHV_EMULATOR_STATUS = 0;
        check_result(unsafe {
            WHvEmulatorTryMmioEmulation(
                self.emulator,
                &mut callbacks_context as *mut _ as *mut VOID,
                vp_context,
                mmio_instruction_context,
                &mut return_status,
            )
        })?;
        Ok(return_status)
    }
}

impl<'a, T: 'a> Drop for Emulator<'a, T>
where
    T: EmulatorCallbacks,
{
    fn drop(&mut self) {
        check_result(unsafe { WHvEmulatorDestroyEmulator(self.emulator) }).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std;

    struct TestCallbacks {}

    impl EmulatorCallbacks for TestCallbacks {
        fn io_port(
            &mut self,
            _context: *const VOID,
            _io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
        ) -> HRESULT {
            S_OK
        }
        fn memory(
            &mut self,
            _context: *const VOID,
            _memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
        ) -> HRESULT {
            S_OK
        }
        fn get_virtual_processor_registers(
            &mut self,
            _context: *const VOID,
            _register_names: &[WHV_REGISTER_NAME],
            _reg_values: &mut [WHV_REGISTER_VALUE],
        ) -> HRESULT {
            S_OK
        }
        fn set_virtual_processor_registers(
            &mut self,
            _context: *const VOID,
            _register_names: &[WHV_REGISTER_NAME],
            _reg_values: &[WHV_REGISTER_VALUE],
        ) -> HRESULT {
            S_OK
        }
        fn translate_gva_page(
            &mut self,
            _context: *const VOID,
            _gva: WHV_GUEST_VIRTUAL_ADDRESS,
            _translate_flags: WHV_TRANSLATE_GVA_FLAGS,
            _translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
            _gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
        ) -> HRESULT {
            S_OK
        }
    }

    #[test]
    fn test_create_delete_emulator() {
        let mut callbacks = TestCallbacks {};
        let e = Emulator::new(&mut callbacks).unwrap();
        drop(e);
    }

    #[test]
    fn test_try_io_emulation() {
        let context = std::ptr::null_mut();
        let mut vp_context: WHV_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
        let mut io_instruction_context: WHV_X64_IO_PORT_ACCESS_CONTEXT =
            unsafe { std::mem::zeroed() };

        // Without this WHvEmulatorTryIoEmulation returns E_INVALIDARG
        vp_context.InstructionLengthCr8 = 0xF;

        let mut callbacks = TestCallbacks {};
        let mut e = Emulator::new(&mut callbacks).unwrap();
        let _return_status = e.try_io_emulation(context, &vp_context, &mut io_instruction_context)
            .unwrap();
    }

    #[test]
    fn test_try_mmio_emulation() {
        let context = std::ptr::null_mut();
        let vp_context: WHV_VP_EXIT_CONTEXT = unsafe { std::mem::zeroed() };
        let mmio_instruction_context: WHV_MEMORY_ACCESS_CONTEXT = unsafe { std::mem::zeroed() };

        let mut callbacks = TestCallbacks {};
        let mut e = Emulator::new(&mut callbacks).unwrap();
        let _return_status = e.try_mmio_emulation(context, &vp_context, &mmio_instruction_context)
            .unwrap();
    }

}
