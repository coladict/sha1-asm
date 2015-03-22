[BITS 64]
[DEFAULT REL]

;default build with nasm -o sha1.obj -f win64 -DWIN64 sha1.asm

;Calling conventions for Windows and everything else. Just in case. Quote from wikipedia:
;The calling convention of the System V AMD64 ABI is followed on Solaris, Linux, FreeBSD, Mac OS X, and other UNIX-like or POSIX-compliant operating systems.

;The Windows calling convention information is taken from MSDN

;V - VOLATILE. CAN BE FREELY DESTROYED.
;number - 0-BASED PARAMETER INDEX\
;P - PRESERVE. MUST COME BACK THE SAME AS IT WENT IN
;R - USED AS RETURN VALUE
;S3 - used instead of RCX for system calls in Linux
;	    RAX  RBX  RCX  RDX  RDI  RSI  RBP  RSP  R8   R9   R10  R11  R12  R13  R14  R15  XMM0 XMM1 XMM2 XMM3 XMM4 XMM5 XMM6 XMM7
;WIN64	RV   P    V0   V1   P    P    P    -    V2   V3   V    V    P    P    P    P    RV0  V1   V2   V3   ?    ?    ?    ?
;LINUX	RV   P    V3   V2   V0   V1   P    -    V4   V5   VS3  V    P    P    P    P    V0   V1   V2   V3   V4   V5   V6   V7
global doSHA1

segment code use64 class='CODE'

;typedef struct {
;	uint32_t H0,
;	uint32_t H1,
;	uint32_t H2,
;	uint32_t H3,
;	uint32_t H4
; } SHA1_DIGEST;

; function prototype:
; void doSHA1(SHA1_DIGEST* bufout, void* bufin, unsigned int bufsize);
; bufout must be at least 121 bytes
doSHA1:
	push rbp
	mov  rbp, rsp
	push rbx
	push r12
	push r13
	push r14
	push r15
; it's almost certainly possible to optimize this to use less non-volatile registers
%ifdef WIN64
; this will be always in the original code as it's windows-only
	push rdi
	push rsi
%endif
; if you want the arguments to be read from the linux registers
	sub rsp, 0x2E0
; spill the registers
; by convention in Windows, the caller must provide room for the first 4 parameters
; however the callee is not required to use them
	mov qword [rbp+0x10], rcx
	mov qword [rbp+0x18], rdx
	mov qword [rbp+0x20], r8
; save the data pointer
; The variable names are as shown in the RFC3174 specifications
; A  => [rsp + 10h]
; B  => [rsp + 18h]
; C  => [rsp + 20h]
; D  => [rsp + 28h]
; E  => [rsp + 30h]
; H0 => [rsp + 38h]
; H1 => [rsp + 40h]
; H2 => [rsp + 48h]
; H3 => [rsp + 50h]
; H4 => [rsp + 58h]
; W[0] => [rsp + 60h]
	mov rax, r8
	xor rdx, rdx
	mov rcx, 64
	div rcx
;   rax now contains number of segments
;   rdx now contains length of last segment
;   save the values, just to be safe
	mov qword [rsp], rax
	mov qword [rsp+0x08], rdx
;whether we move rdx, edx, dx or just dl here affects instruction length, but not the result

;Remember the comparisons: 
; "less" and "greater" are used for comparisons of signed integers
; "above" and "below" are used for unsigned integers

;initialize H0-H4
	mov dword [rsp+0x38], 0x67452301
	mov dword [rsp+0x40], 0xEFCDAB89
	mov dword [rsp+0x48], 0x98BADCFE
	mov dword [rsp+0x50], 0x10325476
	mov dword [rsp+0x58], 0xC3D2E1F0
	mov rsi, qword [rbp+18h]
	
.buffer_read:
	lea rdi, [rsp+60h]
	mov rax, qword [rsp]
	cmp rax, 0
	jz short .last_block
	jl .extra_padding_block ; signed comparison
;this is not the last buffer block
	mov ecx, 64
	cld
	rep movsb
	dec rax
	mov qword [rsp], rax
	jmp .start_process_block
.last_block:
	mov rcx, qword [rsp+0x08]
	dec rax
	mov qword [rsp], rax
	mov rax, rcx
	cld
	rep movsb

	mov byte [rdi], 0x80
	inc rdi
;do we need an extra block for the padding
	cmp eax, 56
	jb short .do_short_padding ;no we don't

;we do need extra block for padding
	xor rax, rax
	mov qword [rsp+0x08], rax
.add_lesser_zero_byte:
	cmp ecx, 64
	je .start_process_block
	mov byte [rdi], 0
	inc ecx
	inc rdi
	jmp short .add_lesser_zero_byte	
	
.do_short_padding:
	mov ecx, eax
.add_one_zero_byte:
	cmp ecx, 55
	je short .add_the_length
	mov byte [rdi], 0
	inc ecx
	inc rdi
	jmp short .add_one_zero_byte

.add_the_length:
	xor rcx, rcx
	dec rcx
	mov qword [rsp+0x08],rcx
	shl r8, 3 ; turn bytes count into bits, because someone thought this algorithm will survive past the era of 8-bit bytes
	bswap qword r8 ; make it big endian, because someone thought big-endians will rule the world
	mov qword [rdi], r8
	jmp short .start_process_block
	
.extra_padding_block:
	mov rcx, qword [rsp+0x08]
	cmp rcx, 0
	jl .do_finish ;the extra padding block is already processed into the hash
	xor rax, rax
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	mov qword[rdi], rax
	add rdi, 0x08
	dec rax
	mov qword [rsp+0x08], rax
	mov r8, qword [rbp+0x20]
	shl r8, 0x03 ; turn bytes count into bits
	bswap qword r8 ;make it big endian
	mov qword [rdi], r8
	jmp short .start_process_block

.mark_last_block:
	xor rcx, rcx
	mov qword [rbp+0x20], rcx

.start_process_block:
	xor rcx, rcx
	lea rdi, [rsp+60h]
	mov ecx, 0x10

	;r10 and r11 are both volatile in all systems
.first_loop:
	xor r11, r11
	mov r10d, dword [rdi+4*rcx-12]
	bswap dword r10d
	xor r11d, r10d
	mov r10d, dword [rdi+4*rcx-32]
	bswap dword r10d
	xor r11d, r10d
	mov r10d, dword [rdi+4*rcx-56]
	bswap dword r10d
	xor r11d, r10d
	mov r10d, dword [rdi+4*rcx-64]
	bswap dword r10d
	xor r11d, r10d
	rol r11d, 0x01
	bswap dword r11d
	mov dword [rdi+4*rcx], r11d
	inc ecx
	cmp ecx, 0x50
	jb short .first_loop

; A  => [rsp + 10h]
; B  => [rsp + 18h]
; C  => [rsp + 20h]
; D  => [rsp + 28h]
; E  => [rsp + 30h]
	mov ebx, dword [rsp + 0x38] ; read H0 into A
	mov r12d, dword [rsp + 0x40] ; read H1 into B
	mov r13d, dword [rsp + 0x48] ; read H2 into C
	mov r14d, dword [rsp + 0x50] ; read H3 into D
	mov r15d, dword [rsp + 0x58] ; read H4 into E

	xor rcx, rcx
.loopt0:
	;calculate f(t,B,C,D) first into eax
	mov eax, r12d
	mov r11d, r12d
	and eax, r13d
	not r11d
	and r11d, r14d
	or  eax, r11d
	; eax now contains  f(t,B,C,D) when t < 20
	mov r11d, ebx
	rol r11d, 0x05
	add eax, r11d ; TEMP =  ROTL^5(A) + f(t;B,C,D)
	add eax, r15d ; TEMP =  ROTL^5(A) + f(t;B,C,D) + E
	mov r11d, dword [rdi + 4*rcx]
	bswap r11d
	add eax, r11d; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t)
	add eax, 0x5A827999; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t) + K(t)

	mov r15d, r14d
	mov r14d, r13d
	ror r12d, 0x02
	mov r13d, r12d
	mov r12d, ebx
	mov ebx, eax

	inc ecx
	cmp ecx, 0x14
	jb short .loopt0

.loopt20:
	;calculate f(t,B,C,D) first into eax
	mov eax, r12d
	xor eax, r13d
	xor eax, r14d
	; eax now contains  f(t,B,C,D) when 20 <= t < 40
	mov r11d, ebx
	rol r11d, 0x05
	add eax, r11d ; TEMP =  ROTL^5(A) + f(t;B,C,D)
	add eax, r15d ; TEMP =  ROTL^5(A) + f(t;B,C,D) + E
	mov r11d, dword [rdi + 4*rcx]
	bswap r11d
	add eax, r11d; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t)
	add eax, 0x6ED9EBA1; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t) + K(t)

	mov r15d, r14d
	mov r14d, r13d
	ror r12d, 0x02
	mov r13d, r12d
	mov r12d, ebx
	mov ebx, eax

	inc ecx
	cmp ecx, 0x28
	jb short .loopt20

.loopt40:
	;calculate f(t,B,C,D) first into eax
	mov eax, r12d ;r12d is B
	and eax, r13d; eax = B AND C
	mov r11d, r12d; r11d = B
	and r11d, r14d; r11d = B AND D
	or eax, r11d; eax = (B AND C) OR (B AND D)
	mov r11d, r13d; r11d = C
	and r11d, r14d; r11d = C AND D
	or eax, r11d
	; eax now contains  f(t,B,C,D) when 40 <= t < 60
	mov r11d, ebx; r11d = A
	rol r11d, 0x05; r11d = rotl(5,A)
	add eax, r11d ; TEMP =  ROTL^5(A) + f(t;B,C,D)
	add eax, r15d ; TEMP =  ROTL^5(A) + f(t;B,C,D) + E
	mov r11d, dword [rdi + 4*rcx]
	bswap r11d
	add eax, r11d; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t)
	add eax, 0x8F1BBCDC; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t) + K(t)

	mov r15d, r14d
	mov r14d, r13d
	ror r12d, 0x02
	mov r13d, r12d
	mov r12d, ebx
	mov ebx, eax

	inc ecx
	cmp ecx, 0x3C
	jb short .loopt40

.loopt60:

	;calculate f(t,B,C,D) first into eax
	mov eax, r12d
	xor eax, r13d
	xor eax, r14d
	; eax now contains  f(t,B,C,D) when 60 <= t < 80
	mov r11d, ebx
	rol r11d, 0x05
	add eax, r11d ; TEMP =  ROTL^5(A) + f(t;B,C,D)
	add eax, r15d ; TEMP =  ROTL^5(A) + f(t;B,C,D) + E
	mov r11d, dword [rdi + 4*rcx]
	bswap r11d
	add eax, r11d; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t)
	add eax, 0xCA62C1D6; TEMP = ROTL^5(A) + f(t;B,C,D) + E + W(t) + K(t)

	mov r15d, r14d
	mov r14d, r13d
	ror r12d, 0x02
	mov r13d, r12d
	mov r12d, ebx
	mov ebx, eax

	inc ecx
	cmp ecx, 0x50
	jb short .loopt60
	
	add dword [rsp + 0x38], ebx		;H0 = H0 + A
	add dword [rsp + 0x40], r12d	;H1 = H1 + B
	add dword [rsp + 0x48], r13d	;H2 = H2 + C
	add dword [rsp + 0x50], r14d	;H3 = H3 + D
	add dword [rsp + 0x58], r15d	;H4 = H4 + E

	jmp .buffer_read

.do_finish:
	mov ebx,	dword [rsp + 0x38]	;H0 = H0 + A
	mov r12d,	dword [rsp + 0x40] 	;H1 = H1 + B
	mov r13d,	dword [rsp + 0x48] 	;H2 = H2 + C
	mov r14d,	dword [rsp + 0x50] 	;H3 = H3 + D
	mov r15d,	dword [rsp + 0x58]	;H4 = H4 + E
	mov rdi,	qword [rbp+0x10]
	mov dword [rdi], ebx
	mov dword [rdi+0x04], r12d
	mov dword [rdi+0x08], r13d
	mov dword [rdi+0x0C], r14d
	mov dword [rdi+0x10], r15d

;clean-up, go home
	add rsp, 0x2E0
%ifdef WIN64
	pop rsi
	pop rdi
%endif
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	pop rbp
	ret
