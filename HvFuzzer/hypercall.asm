.CODE 

PUBLIC Hypercall

; 
; Hypercall wrapper
;
; Inputs:
; RCX = Input PCPU_REG_64
; RDX = Output PCPU_REG_64
;
; Outputs:
; RAX = HV_STATUS from vmcall
;
Hypercall PROC
    
    push rbp

    push rsi
    push rdi
    push rdx                                ; Store output PCPU_REG_64
    
    mov rsi, rcx

    ;
    ; Hypercall inputs
    ; RCX = Hypercall input value
    ; RDX = Input param GPA
    ; R8  = Output param GPA 
    ;
    mov rcx, qword ptr [rsi+10h]
    mov rdx, qword ptr [rsi+18h]
    mov r8,  qword ptr [rsi+30h]

    mov rax, qword ptr [rsi+00h]
    mov rbx, qword ptr [rsi+08h]
    mov rdi, qword ptr [rsi+28h]
    mov r9,  qword ptr [rsi+38h]
    mov r10, qword ptr [rsi+40h]
    mov r11, qword ptr [rsi+48h]
    
    int 3

    vmcall

    ;
    ; Move any output data to PCPU_REG_64
    ;
    pop rsi                                 ; RSI now contains output PCPU_REG_64
    mov qword ptr [rsi+00h], rax
    mov qword ptr [rsi+08h], rbx
    mov qword ptr [rsi+10h], rcx
    mov qword ptr [rsi+18h], rdx
    mov qword ptr [rsi+28h], rdi
    mov qword ptr [rsi+30h], r8
    mov qword ptr [rsi+38h], r9
    mov qword ptr [rsi+40h], r10
    mov qword ptr [rsi+48h], r11
    ;mov qword ptr [rsi+20h], rsi

    pop rdi
    pop rsi

    pop rbp
    ret
Hypercall ENDP


END
