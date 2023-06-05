BITS 32

SECTION .text
global main

main:
push eax
	push ecx
	push edx
	push esi
	push edi
	push ebx

	 mov eax, 0x4 ; #define __NR_write 4
            ; ssize_t write(int fd, const void *buf, size_t count);
            ;
     mov ebx, 1 ; fd standard console output == 1
     ;mov ecx, [rel $+hello-$] ; buf
     call x86_get_thunk
     add ecx, 0x1a
     mov edx, 19 ; count
     int 0x80
     	pop ebx
     	pop edi
     	pop esi
     	pop edx
     	pop ecx
     	pop eax

push 0x8049060
ret

x86_get_thunk:
    mov ecx, [esp]
    ret

hello: db "backdoor success!",33,10