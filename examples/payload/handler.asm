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

.globl interrupt_handler_host
.globl interrupt_handler_guest
.align 4
.intel_syntax noprefix

.macro SAVE_VOLATILE_REGS 
mov [rsp-0x08], rax
mov [rsp-0x10], rcx
mov [rsp-0x18], rdx
mov [rsp-0x20], r8
mov [rsp-0x28], r9
mov [rsp-0x30], r10
mov [rsp-0x38], r11
movdqu xmmword ptr [rsp-0x48], xmm0
movdqu xmmword ptr [rsp-0x58], xmm1
movdqu xmmword ptr [rsp-0x68], xmm2
movdqu xmmword ptr [rsp-0x78], xmm3
movdqu xmmword ptr [rsp-0x88], xmm4
movdqu xmmword ptr [rsp-0x98], xmm5
sub rsp, 0x98
.endm

.macro RESTORE_VOLATILE_REGS
add rsp, 0x98
mov rax, [rsp-0x08]
mov rcx, [rsp-0x10]
mov rdx, [rsp-0x18]
mov r8,  [rsp-0x20]
mov r9,  [rsp-0x28]
mov r10, [rsp-0x30]
mov r11, [rsp-0x38]
movdqu xmm0, xmmword ptr [rsp-0x48]
movdqu xmm1, xmmword ptr [rsp-0x58]
movdqu xmm2, xmmword ptr [rsp-0x68]
movdqu xmm3, xmmword ptr [rsp-0x78]
movdqu xmm4, xmmword ptr [rsp-0x88]
movdqu xmm5, xmmword ptr [rsp-0x98]
.endm

interrupt_handler_host:
    SAVE_VOLATILE_REGS
    call log_interrupt_from_host
    RESTORE_VOLATILE_REGS
    iretq

interrupt_handler_guest:
    SAVE_VOLATILE_REGS
    call log_interrupt_from_guest
    RESTORE_VOLATILE_REGS
    iretq



