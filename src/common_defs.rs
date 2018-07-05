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

pub type HRESULT = c_int;
pub type UINT8 = c_uchar;
pub type UINT32 = c_uint;
pub type UINT64 = c_longlong;
pub type VOID = c_void;
pub type BOOL = c_int;
pub type UINT16 = c_ushort;

pub const S_OK: HRESULT = 0;
pub const E_FAIL: HRESULT = -2147467259; // 0x80004005;
pub const E_INVALIDARG: HRESULT = -2147024809; // 0x80070057

// TODO (alexpilotti): transform into a macro
pub fn check_result(res: HRESULT) -> Result<(), HRESULT> {
    match res {
        S_OK => Ok(()),
        _ => Err(res),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_ok() {
        check_result(S_OK).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_check_result_fail() {
        check_result(E_INVALIDARG).unwrap();
    }
}
