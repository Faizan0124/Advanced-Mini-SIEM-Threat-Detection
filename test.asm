INCLUDE C:\irvine\Irvine32.inc
.data
msg BYTE "Hello from Irvine32",0
.code
main PROC
    mov edx, OFFSET msg
    call WriteString
    call Crlf
    exit
main ENDP
END main
