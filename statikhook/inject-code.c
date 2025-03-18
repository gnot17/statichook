#include "get_commutate_pointer.c" 

// write your code here, keep the location of the line "#include "get_commutate_pointer.c" unchanged

// Below is a simple template, remove it
void Func1()
{
    void(*Call)() = (void(*)())get_commutate_pointer(0x123456);
    Call();
}
void Hook1()
{
    Func1();
    
    void(*Call)() = (void(*)())get_commutate_pointer(0x123456);
    Call();
}