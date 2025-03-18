long long get_commutate_pointer(long long ofuncoff)
{
    long long offset = 0;
    asm volatile(
        "stp x0, x1, [sp, #-16]!\n"
        "1:\n"
        "adr x0, 1b\n"
        "bic x0, x0, #0x3fff\n"
        "mov %0, x0\n"
        "ldp x0, x1, [sp], #16\n"
        : "=r"(offset)
        :
        : "x0", "x1"
    );
    offset -= 0x4000;
    
    for (int i = 0; i < 1024; i++)
    {
        if(*(long long*)(offset + i*16 + 8) == ofuncoff)
        {
            return offset + i*16;
        }
    }
    return 0x141516;
}

