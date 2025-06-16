format binary
use32


ScanProc: ; (Pattern, Buffer)
    push        ebp                             ; start of building a stack frame
    mov         ebp, esp                        ; storing the stack frame in ebp
    sub         esp, 0x0008                     ; Adding space for local variables (8 bytes)
    push        ebx ecx edx esi edi             ; store the registers on the stack

    mov         edx, DWORD [ebp + 0x0008]       ; edx    = Pattern (Struct Pointer)
    mov         eax, DWORD [edx]                ; offset = Pattern.Length

    test        eax, eax                        ; if eax == 0:
    je          .exit                           ;     GoTo .exit

    dec         eax                             ; i = i - 1
    mov         ebx, DWORD [edx + 0x0204]
    mov         DWORD [ebp - 0x0004], ebx

    lea         esi, [edx + 0x0004]             ; char* Binary = AddressOf(Pattern.Binary)
    lea         edi, [edx + 0x0104]             ; char* Mask   = AddressOf(Pattern.Mask)

    mov         edx, DWORD [ebp + 0x000C]       ; edx          = Buffer (Struct Pointer)

    mov         ebx, DWORD [edx]                ; Cursor       = Buffer.Base              // Example: 3EC0000
    mov         ecx, DWORD [edx + 0x0004]       ; ScanEnd      = Buffer.End               // Example: 4C1F000 (Base+Size)

    mov         DWORD [ebp - 0x0008], ebx       ; Local base = Cursor

    sub         ecx, eax                        ; ScanEnd      = ScanEnd - i              // 0x4C1F000 - 6 = 04C1EFFA
    mov         dl, BYTE [esi + eax]            ; LastByte     = Pattern.Binary[i]        // Example: Binary[6] = CF


.loop:
    cmp         ebx, ecx                        ; if (Cursor >= ScanEnd)
    jae         .returnZero                     ;     GoTo .returnZero

                                                ; Check current byte + 6 with last byte of pattern
    cmp         BYTE [ebx + eax], dl            ; if (ReadByte[Cursor + i] != LastByte)
    jne         .next                           ;     GoTo .next

    push        eax                             ; n = i

.patternLoop:
    dec         eax                             ; n = n - 1
    cmp         BYTE [edi + eax], 'x'           ; if (Mask[n] != 'x')
    jne         .checkLoopDone                  ;     GoTo .checkLoopDone

    mov         dh, BYTE [esi + eax]            ; dh = Binary[n]
    cmp         BYTE [ebx + eax], dh            ; if (ReadByte[ScanStart + n] != Binary[n])
    jne         .continue                       ;     GoTo .continue

.checkLoopDone:
    test        eax, eax                        ; if (n != 0)
    jne         .patternLoop                    ;     GoTo .patternLoop

.continue:
    pop         eax                             ; recycle n
    jne         .next                           ; GoTo .next

    mov         eax, ebx                        ; returnValue = Cursor
    mov         ebx, DWORD [ebp - 0x0008]       ; ebx = Buffer.Base
    sub         eax, ebx                        ; returnValue = returnValue - Buffer.Base
    jmp         .exit                           ; return Cursor

.next:
    inc         ebx                             ; Cursor = Cursor + 1
    jmp         .loop                           ; GoTo .loop

.returnZero:
    xor         eax, eax                        ; return 0

.exit:
    test        eax, eax                        ; checks if returnValue == 0
    jz          .skipOffset                     ; if it is zero, goto .skipOffset
    add         eax, DWORD [ebp - 0x0004]       ; add or subtract the offset of the pattern

.skipOffset:
    pop         edi esi edx ecx ebx             ; restore the registers to the values before the function got called
    add         esp, 0x0008                     ; Remove local variables
    leave                                       ; leaves the stack frame
    ret         0x8                             ; returns to the calling address. 0x8 cleans up 8 bytes on the stack
                                                ; because we passed 2 parameters which are 2 pushes == 0x8 Bytes
