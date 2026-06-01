SECTIONS
{
    .out (READONLY) :
    {
        *(.entry)
        *(.text*)
        *(.rodata*)
        *(.got*)
    }
}
