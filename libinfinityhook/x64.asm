extern halCounterQueryRoutine:qword
extern keQueryPerformanceCounterHook:PROC


.CODE

checkLogger PROC
    push rcx
    mov rcx,rsp
    call keQueryPerformanceCounterHook
    pop rcx
    mov rax, halCounterQueryRoutine
    jmp rax
checkLogger ENDP
end


END