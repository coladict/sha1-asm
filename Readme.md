# Why do this?
I needed a SHA1 function and at first I tried looking at OpenSSL to
see if I can copy it and if their license allows me to. Unfortunately
they use too many completely unnecessary macros, in my opinion. The
other problem was that they use three whole functions for getting a
hash, when one should suffice. Secondly, because the algorithm
uses big-endian words, that requires byte swapping. That is always
painful to look at in C, because not every compiler supports that
intrinsic function. It also uses rotations, which are also not natively
supported in C. Both of these factors make the code a bit uglier and
inefficient.

# Why 64-bit only?
What is this? 2007? Grow up!

# Why is it written only for Windows?
Because I despise GNU's so-called "autotools". Though if you really
want to, you can include the following lines in your Makefile
>     sha1.o: sha1.asm
>         nasm -f elf64 -o sha1.o sha1.asm

or whatever the supported x64 linker format is for Linux compilation.
I've added comments about the differences in parameter reading you would
also need to make. However I don't know if Linux calling conventions
require the compiler to provide the space for spilling the registers.
Look for all RBP usages if you need to change that.

# Why Netwide Assembler?
Because I like it.

# How do I add this to my Visual Studio build?
Ok, that's kind of long and the instructions are for "Visual Studio
Express 2013 for Windows Desktop" and may differ for past (or future)
versions. Make sure you're adding it to All Configurations on the x64 platform.

Put both sha1.h and sha1.asm files in your sources directory and add them
as existing items. Open your project's properties and first go to VC++
Directories. Add your Nasm installation path to the Executable Directories.
Expand the Linker tree and open up Input. Add an extra dependency `$(IntDir)sha1.obj`.
Now go to Custom Build Step and add the Command Line:
`nasm -o "$(IntDir)sha1.obj" -f win64 -DWIN64 "$(ProjectDir)sha1.asm"`
Set it to execute after Compile and before Link. That's it.

# Do I need anything from the included .cpp file?
No. It's only provided as a test, using the RFC3174 implementation for comparison.


# Copyright notices
### License for the Assembler implementation:

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                        Version 2, December 2004 

     Copyright (C) 2015 Jordan Gigov <coladict@gmail.com> 

     Everyone is permitted to copy and distribute verbatim or modified 
     copies of this license document, and changing it is allowed as long 
     as the name is changed. 

                DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
       TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

      0. You just DO WHAT THE FUCK YOU WANT TO.

To clarify: you can change the license only if you change the project's name.

### The following Copyright notice is presented for the "C" implementation, taken from the RFC3174 document, in compliance with it.

Copyright (C) The Internet Society (2001). All Rights Reserved.
This document and translations of it may be copied and furnished to
others, and derivative works that comment on or otherwise explain it
or assist in its implementation may be prepared, copied, published
and distributed, in whole or in part, without restriction of any
kind, provided that the above copyright notice and this paragraph are
included on all such copies and derivative works. However, this
document itself may not be modified in any way, such as by removing
the copyright notice or references to the Internet Society or other
Internet organizations, except as needed for the purpose of
developing Internet standards in which case the procedures for
copyrights defined in the Internet Standards process must be
followed, or as required to translate it into languages other than
English.