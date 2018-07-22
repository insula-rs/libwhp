OUTPUT_FORMAT(binary)
SECTIONS
{
    .start : { *(.start) }
    .text : { *(.text*) }
    .rodata : { *(.rodata) }
    . = 0x100000;
    .data : { *(.data) }
}
