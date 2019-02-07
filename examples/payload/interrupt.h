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

#ifndef _INTERRUPT_H_
#define _INTERRUPT_H_

#define NUM_IDT_ENTRIES 256
#define NUM_GDT_ENTRIES 8

#define APIC_MMIO_OFFSET_EOI_LOW 0x0b0
#define APIC_MMIO_OFFSET_EOI_HIGH 0x0c0
#define APIC_MMIO_OFFSET_ICR_LOW 0x300
#define APIC_MMIO_OFFSET_ICR_HIGH 0x310

#define APIC_BASE_MSR 0x1b8

#define APIC_BASE 0x0fee0000

#define GDT_NULL             0x0000
#define GDT_R0_CODE          0x0008
#define GDT_R0_DATA          0x0010
#define GDT_R3_DATA          0x0018
#define GDT_R3_CODE          0x0020
#define GDT_SYS_TSS          0x0028 // System GDT entries are twice as wide

#define HOST_INT_VECTOR 0x35
#define GUEST_INT_VECTOR 0x36

// Struct for a single IDT entry
typedef union _IDT_ENTRY64
{
    struct
    {
        uint16_t offset_low;
        uint16_t selector;       /* GDT R0 Code Segment */
        uint16_t ist_index:3;
        uint16_t reserved0:5;
        uint16_t type:5;
        uint16_t dpl:2;
        uint16_t present:1;
        uint16_t offset_middle;
        uint32_t offset_high; 
        uint32_t reserved1;
        
    } fields;
    uint64_t alignment;
} IDT_ENTRY64, *PIDT_ENTRY64;

// This structure contains the value of one GDT entry.
typedef struct _GDT_ENTRY64
{
   uint16_t limit_low;           // The lower 16 bits of the limit.
   uint16_t base_low;            // The lower 16 bits of the base.
   uint8_t base_middle;          // The next 8 bits of the base.
   uint8_t access;               // Access flags, determine what ring this segment can be used in.
   uint8_t flags_limit_high;
   uint8_t base_high;            // The last 8 bits of the base.
} __attribute__((packed)) GDT_ENTRY64, *PGDT_ENTRY64;

// Struct to describe a descriptor table (IDT, GDT), required for LIDT/LGDT
typedef struct _DT_PTR64
{
    uint16_t padding[3];
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) DT_PTR64, *PDT_PTR64;

void load_idt_register(void* idt_ptr)
{
    __asm__ __volatile__("lidt %0" :: "m"(*(uint64_t*)idt_ptr));
}

void load_gdt_register(void* gdt_ptr)
{
    __asm__ __volatile__("lgdt %0" :: "m"(*(uint64_t*)gdt_ptr));
}

void enable_interrupt_flag()
{
    __asm__ __volatile__("sti");
}

void clear_interrupt_flag()
{
    __asm__ __volatile__("cli");
}

void store_idt_register(void* idt_ptr)
{
    __asm__ __volatile__("sidt %0" : "=m"(*(uint64_t*)idt_ptr));
}

#endif
