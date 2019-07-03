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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "helpers.h"
#include "interrupt.h"

extern void interrupt_handler_host();
extern void interrupt_handler_guest();

#define CPUID_EXT_HYPERVISOR ((uint32_t)(1 << 31))

#define LOG_PORT 42
#define MAX_VALUE_CHARS 11
#define BUF_SIZE 1024

static void out_string(uint16_t port, char* value);

// IDT and GDT for this guest
IDT_ENTRY64 Idt[NUM_IDT_ENTRIES];
GDT_ENTRY64 Gdt[NUM_GDT_ENTRIES];

// Set that interrupts have been enabled when handling interrupt from host
int interrupts_enabled = 0;

static void outb(uint16_t port, uint8_t value) {
    asm("outb %0, %1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

__attribute__((unused))
static void inb(uint16_t port, uint8_t* value) {
    asm volatile("inb %1, %0" : "=a"(*value) : "Nd"(port));
}

static void out_string(uint16_t port, char* value) {
    const char* p;
    for (p = value; *p; ++p)
        outb(port, *p);
}

static void out_string_max(uint16_t port, char* value, uint32_t max_len) {
    const char* p;
    for (p = value; *p && (p - value) < max_len; ++p)
        outb(port, *p);
}

static void get_cpuid(unsigned leaf, unsigned* regs) {
    asm volatile("cpuid": "=a" (regs[0]), "=b" (regs[1]),
                 "=c" (regs[2]), "=d" (regs[3]) : "a" (leaf));
}

static void cpu_set_msr(uint32_t msr, uint32_t lo, uint32_t hi) {
    asm volatile("wrmsr" : : "a"(lo), "d"(hi), "c"(msr));
}

static void cpu_get_msr(uint32_t msr, uint32_t *lo, uint32_t *hi) {
    asm volatile("rdmsr" : "=a"(*lo), "=d"(*hi) : "c"(msr));
}

static void halt(uint32_t value) {
    asm("hlt" : /* empty */ : "a" (value) : "memory");
}

static inline void mmio_writeq(uint64_t val, volatile void *addr)
{
    asm volatile("mov" "q" " %0, %1": :
                 "r" (val), "m" (*(volatile uint64_t *)addr) :"memory");
}

static inline uint64_t mmio_readq(volatile void *addr)
{
    uint64_t val;
    asm volatile("mov" "q" " %1, %0":
                 "=r" (val): "m" (*(volatile uint64_t *)addr) :"memory");
    return val;
}

static inline void mmio_writeb(uint8_t val, volatile void *addr)
{
    asm volatile("mov %0, %1": :
                 "r" (val), "m" (*(volatile uint8_t *)addr) :"memory");
}

static inline uint8_t mmio_readb(volatile void *addr)
{
    uint8_t val;
    asm volatile("mov" "b" " %1, %0":
                 "=r" (val): "m" (*(volatile uint8_t *)addr) :"memory");
    return val;
}

/* Small helper function to print a decimal value and a corresponding
   description, lacking APIs like snprintf.
*/
__attribute__((unused))
void print_dec(uint32_t value, char* desc)
{
    char buf[BUF_SIZE];
    char value_str[MAX_VALUE_CHARS];
    uint32_t len;
    
    len = itoa(value, value_str);

    memcpy(buf, value_str, MAX_VALUE_CHARS);
    memcpy(&buf[len], desc, BUF_SIZE - MAX_VALUE_CHARS - 1);

    out_string(LOG_PORT, buf);
}

static void gdt_set_descriptor(PGDT_ENTRY64 gdt, uint32_t index, uint32_t base,
    uint32_t limit, uint8_t access, uint8_t flags)
{
    gdt[index].base_low = (base & 0xffff);
    gdt[index].base_middle = (base >> 16) & 0xff;
    gdt[index].base_high = (base >> 24) & 0xff;
    
    gdt[index].limit_low = (limit & 0xffff);

    gdt[index].flags_limit_high = (limit >> 16) & 0xf;
    gdt[index].flags_limit_high |= flags & 0xf0;

    gdt[index].access = access;
}

void
initialize_gdt(PGDT_ENTRY64 gdt)
{
    DT_PTR64 gdt_ptr = { 0 };
    uint32_t gdt_size = sizeof(GDT_ENTRY64) * NUM_GDT_ENTRIES;

    memset(gdt, 0, gdt_size);

    // Fill in the special GDT pointer to be loaded into the GDT Register
    gdt_ptr.limit = gdt_size - 1;
    gdt_ptr.base = (uintptr_t)gdt;

    gdt_set_descriptor(gdt, 0, 0, 0, 0, 0);                // Null segment
    gdt_set_descriptor(gdt, 1, 0, 0xffffffff, 0x98, 0x20); // KM Code segment
    gdt_set_descriptor(gdt, 2, 0, 0xffffffff, 0x93, 0xcf); // KM Data segment
    gdt_set_descriptor(gdt, 3, 0, 0xffffffff, 0xfa, 0xcf); // UM code segment
    gdt_set_descriptor(gdt, 4, 0, 0xffffffff, 0xf2, 0xcf); // UM data segment

    load_gdt_register(&(gdt_ptr.limit));
}

void initialize_idt(PIDT_ENTRY64 idt)
{
    DT_PTR64 idt_ptr = { 0 };
    
    uint32_t idt_size = sizeof(IDT_ENTRY64) * NUM_IDT_ENTRIES;

    memset(idt, 0, idt_size);

    // Fill in the special IDT pointer to be loaded into the IDT Register
    idt_ptr.limit = idt_size - 1;
    idt_ptr.base = (uintptr_t)idt;

    // Point the processor's internal register to the new IDT
    load_idt_register(&(idt_ptr.limit));
}

static void register_interrupt_handler(PIDT_ENTRY64 idt, uint32_t vector, void* handler)
{
    PIDT_ENTRY64 idte;

    // Get the address of the IDT entry at the specified vector
    idte = &idt[vector];

    // Set the data at that entry
    idte->fields.offset_low = (uint16_t)((uint64_t)handler & 0xffff);
    idte->fields.offset_middle = (uint16_t)(((uint64_t)handler >> 16) & 0xffff);
    idte->fields.offset_high = (uint32_t)((uint64_t)handler >> 32);
    idte->fields.selector = GDT_R0_CODE;
    idte->fields.ist_index = 0;
    idte->fields.reserved0 = 0;
    idte->fields.type = 0xe;
    idte->fields.dpl = 0;
    idte->fields.present = 1;
    idte->fields.reserved1 = 0;
}

void clear_apic_eoi()
{
    uint32_t* eoi_reg_low = (uint32_t*)(APIC_BASE + APIC_MMIO_OFFSET_EOI_LOW);
    uint32_t* eoi_reg_high = (uint32_t*)(APIC_BASE + APIC_MMIO_OFFSET_EOI_HIGH);
    *eoi_reg_high = 0;
    *eoi_reg_low = 0;
}

void log_interrupt_from_host()
{
    out_string(LOG_PORT, "Interrupt sent from host received.\n");

    // Interrupt received. Interrupts are enabled on the host.
    interrupts_enabled = 1;
    clear_apic_eoi();
}

void log_interrupt_from_guest()
{
    out_string(LOG_PORT, "Interrupt sent from guest received.\n");
    clear_apic_eoi();
}

/*
    Send the IPI by writing to the two Interrupt Command Registers (ICRs). They
    are memory mapped at APIC_BASE + 0x300 (low register) and APIC_BASE + 0x310
    (high register)
    Since our virtual memory is identity mapped, we can just write to the
    expected physical address of APIC_BASE + ICR.
*/
static void apic_send_ipi(uint64_t apic_base, uint32_t high, uint32_t low)
{
    uint32_t* icr_low = (uint32_t*)(apic_base + APIC_MMIO_OFFSET_ICR_LOW);
    uint32_t* icr_high = (uint32_t*)(apic_base + APIC_MMIO_OFFSET_ICR_HIGH);

    out_string(LOG_PORT, "Sending IPI from the guest\n");

    // From the manual, the act of writing to the low doubleword of the ICR
    // causes the IPI to be sent
    *icr_high = high;
    *icr_low = low;
}

void
__attribute__((section(".start")))
_start(void) {
    initialize_gdt(Gdt);
    initialize_idt(Idt);
    
    out_string(LOG_PORT, "Greetings from the guest!\n");

    register_interrupt_handler(Idt, HOST_INT_VECTOR, (void*)interrupt_handler_host);
    register_interrupt_handler(Idt, GUEST_INT_VECTOR, (void*)interrupt_handler_guest);

    enable_interrupt_flag();

    unsigned regs[] = {0, 0, 0, 0};
    get_cpuid(1, regs);
    if (regs[2] == CPUID_EXT_HYPERVISOR) {
        out_string(LOG_PORT, "Hypervisor present\n");
    }

    memset(regs, 0, sizeof(regs));
    get_cpuid(0x40000000, regs);

    char id[13] = {0};
    memcpy(id, &regs[1], 12);
    id[12] = 0;

    out_string(LOG_PORT, "Hypervisor ID: ");
    out_string_max(LOG_PORT, id, sizeof(id));
    out_string(LOG_PORT, "\n");

    unsigned char in_byte;
    inb(43, &in_byte);
    print_dec((uint32_t)in_byte, ": Value obtained via INB IO Port read\n");

    uint32_t lo, hi = 0;
    cpu_get_msr(1, &lo, &hi);
    cpu_set_msr(1, lo + 1, hi + 1);

    // Take advantage of identity memory mapping to read/write an unmapped
    // memory location to generate an MMIO exit
    unsigned char* mmio_buf = (unsigned char*)0x3f00000;

    // Do tests of quad word
    uint64_t data = 0;
    data = mmio_readq(mmio_buf);
    print_dec(data, ": Qword read via MMIO read\n");
    mmio_writeq(data + 1, mmio_buf);

    // Do tests of a single byte
    uint8_t byte = mmio_readb(mmio_buf);
    print_dec((uint32_t)byte, ": Byte read via MMIO read\n");
    mmio_writeb(byte + 1, mmio_buf);


    // Send an IPI to the vector we registered earlier. The host will also use
    // this as a signal to terminate the guest.
    // - Level = 1 = Assert (Bit 14 on) (Must be set to 1 for fixed interrupt
    //   type)
    // - Destination Shorthand = 01 = Self (Bit 18 on). Ignore destination
    //   register (ICR high) and send the IPI to the issuing APIC (self)
    // - Delivery mode = 000 (Fixed)
    // - Destination mode = 0 (Physical)
    uint32_t icr_low_val = 0x00044000 | GUEST_INT_VECTOR;
    apic_send_ipi(APIC_BASE, 0, icr_low_val);

    // Only halt the vcpu if interrupts are not enabled. Otherwise, the host
    // will take care of terminating the guest.
    if (interrupts_enabled == 0) {
        halt(0);
    }

    return;
}
