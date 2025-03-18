# statichook
Tool for creating static code injections into macho-o files for iOS arm64

To run, go to the project folder, compile statichook with the command:

./static-hook-compile.sh

**or**

clang code_statichook.c -o statichook

**Then**

Compile your inject file, named **inject-code.c**:

./inject-code-compile.sh

**or** 

**clang** -arch **arm64** -dynamiclib -fPIC **inject-code.c** -o **injseg_data**

The "**statichook_result**" folder will contain the result, **sign the library** received from there before using it.

If the console output shows "**error in line: <number>**" instead of "**GLOBAL DONE**", then go to this line of code in the **code_statichook.c file** to investigate the problem.

Example of using the tool:

**statichook** /path/to/modifying_file /path/to/inject_code_file **N** addr1 symbol1 addr2 symbol2 ... addrN symbolN

**statichook** /user/gnot/desktop/modifying_file /user/gnot/desktop/inject_code_file **3** 0x1fe4544 **_my_hook_func1** 0x1be3434 **_my_hook_func2** 0x120b8a4 **CALL_ONLY**
