TITLE Mini SIEM Backend Engine   (Mini_SIEM.asm)

; -------------------------------------------------------------------
; This program parses a log file, counts occurrences of various 
; security threats (LOGIN_FAIL, PORT_SCAN, PRIV_ESC, FILE_DELETE), 
; calculates a threat score, determines the threat level, 
; and outputs the results to the standard output.
; -------------------------------------------------------------------

INCLUDE Irvine32.inc

includelib user32.lib
wsprintfA PROTO C :PTR BYTE, :PTR BYTE, :VARARG
lstrlenA PROTO STDCALL :PTR BYTE





.data

stdOutHandle DWORD ?
bytesWritten DWORD ?
num_buf BYTE 20 DUP(0)

fmt_str BYTE "%s",0
fmt_dec BYTE "%u",0
fmt_nl BYTE 13,10,0

; File I/O Variables
filename BYTE "logs.txt",0
fileHandle HANDLE ?
bytesRead DWORD ?

.data?
buffer BYTE 25000000 DUP(?)     ; Buffer to store file contents (up to 25MB)

.data

; Threat Signatures to scan for
str_login BYTE "LOGIN_FAIL",0
str_port  BYTE "PORT_SCAN",0
str_priv  BYTE "PRIV_ESC",0
str_file  BYTE "FILE_DELETE",0

; Lengths of the threat signatures
len_login DWORD 10
len_port  DWORD 9
len_priv  DWORD 8
len_file  DWORD 11

; Metrics Counters
count_lines DWORD 0
count_login DWORD 0
count_port  DWORD 0
count_priv  DWORD 0
count_file  DWORD 0
threat_score DWORD 0

; Output Display Strings
msg_total BYTE "TOTAL_LOGS: ",0
msg_login BYTE "BRUTE_FORCE: ",0
msg_port  BYTE "PORT_SCANS: ",0
msg_priv  BYTE "PRIV_ESC: ",0
msg_file  BYTE "FILE_TAMPERING: ",0
msg_score BYTE "THREAT_SCORE: ",0
msg_level BYTE "THREAT_LEVEL: ",0

; Threat Level Classification Strings
lvl_low   BYTE "Low",0
lvl_med   BYTE "Medium",0
lvl_high  BYTE "High",0
lvl_crit  BYTE "Critical",0

; Error Messages
error_msg BYTE "Error: Unable to open 'logs.txt'.",0

.code
main PROC
    ; ---------------------------------------------------------------
    ; Step 1: Open the log file for reading
    ; ---------------------------------------------------------------
    mov edx, OFFSET filename
    call OpenInputFile
    mov fileHandle, eax
    
    cmp eax, INVALID_HANDLE_VALUE
    jne Read_File
    ; Print error if file cannot be opened
    mov edx, OFFSET error_msg
    call MyWriteString
    call MyCrlf
    jmp Exit_Program

Read_File:
    ; ---------------------------------------------------------------
    ; Step 2: Read the file contents into the buffer
    ; ---------------------------------------------------------------
    mov eax, fileHandle
    mov edx, OFFSET buffer
    mov ecx, SIZEOF buffer
    call ReadFromFile
    mov bytesRead, eax
    
    ; Close the file handle after reading
    mov eax, fileHandle
    call CloseFile

    ; If the file is empty (0 bytes read), skip to printing results
    cmp bytesRead, 0
    je Print_Results

    ; ---------------------------------------------------------------
    ; Step 3: Parse Buffer - Count Total Logs (by counting '\n')
    ; ---------------------------------------------------------------
    mov esi, OFFSET buffer
    mov ecx, bytesRead
    mov count_lines, 0

Count_Lines_Loop:
    mov al, [esi]
    cmp al, 0Ah          ; Check for Line Feed (newline) character
    jne Skip_Line_Inc
    inc count_lines      ; Increment line counter
Skip_Line_Inc:
    inc esi              ; Move to next byte
    loop Count_Lines_Loop

    ; ---------------------------------------------------------------
    ; Step 4: Scan and Count Threat Signatures
    ; ---------------------------------------------------------------
    
    ; Scan for LOGIN_FAIL
    mov esi, OFFSET buffer
    mov edi, OFFSET str_login
    mov ecx, bytesRead
    mov edx, len_login
    call CountSubstring
    mov count_login, eax

    ; Scan for PORT_SCAN
    mov esi, OFFSET buffer
    mov edi, OFFSET str_port
    mov ecx, bytesRead
    mov edx, len_port
    call CountSubstring
    mov count_port, eax

    ; Scan for PRIV_ESC
    mov esi, OFFSET buffer
    mov edi, OFFSET str_priv
    mov ecx, bytesRead
    mov edx, len_priv
    call CountSubstring
    mov count_priv, eax

    ; Scan for FILE_DELETE
    mov esi, OFFSET buffer
    mov edi, OFFSET str_file
    mov ecx, bytesRead
    mov edx, len_file
    call CountSubstring
    mov count_file, eax

    ; ---------------------------------------------------------------
    ; Step 5: Calculate Threat Score
    ; Formula: (LOGIN_FAIL*10) + (PORT_SCAN*20) + (PRIV_ESC*50) + (FILE_DELETE*40)
    ; ---------------------------------------------------------------
    mov eax, count_login
    imul eax, 10
    add threat_score, eax

    mov eax, count_port
    imul eax, 20
    add threat_score, eax

    mov eax, count_priv
    imul eax, 50
    add threat_score, eax

    mov eax, count_file
    imul eax, 40
    add threat_score, eax

Print_Results:
    ; ---------------------------------------------------------------
    ; Step 6: Print Metrics to Standard Output
    ; ---------------------------------------------------------------
    
    ; TOTAL_LOGS
    mov edx, OFFSET msg_total
    call MyWriteString
    mov eax, count_lines
    call MyWriteDec
    call MyCrlf

    ; BRUTE_FORCE
    mov edx, OFFSET msg_login
    call MyWriteString
    mov eax, count_login
    call MyWriteDec
    call MyCrlf

    ; PORT_SCANS
    mov edx, OFFSET msg_port
    call MyWriteString
    mov eax, count_port
    call MyWriteDec
    call MyCrlf

    ; PRIV_ESC
    mov edx, OFFSET msg_priv
    call MyWriteString
    mov eax, count_priv
    call MyWriteDec
    call MyCrlf

    ; FILE_TAMPERING
    mov edx, OFFSET msg_file
    call MyWriteString
    mov eax, count_file
    call MyWriteDec
    call MyCrlf

    ; THREAT_SCORE
    mov edx, OFFSET msg_score
    call MyWriteString
    mov eax, threat_score
    call MyWriteDec
    call MyCrlf

    ; ---------------------------------------------------------------
    ; Step 7: Classify Threat Level using conditional jumps
    ; ---------------------------------------------------------------
    mov edx, OFFSET msg_level
    call MyWriteString
    
    mov eax, threat_score
    cmp eax, 50
    jl Level_Low
    cmp eax, 100
    jle Level_Medium
    cmp eax, 200
    jle Level_High
    jmp Level_Critical

Level_Low:
    mov edx, OFFSET lvl_low
    jmp Print_Level
Level_Medium:
    mov edx, OFFSET lvl_med
    jmp Print_Level
Level_High:
    mov edx, OFFSET lvl_high
    jmp Print_Level
Level_Critical:
    mov edx, OFFSET lvl_crit

Print_Level:
    call MyWriteString
    call MyCrlf

Exit_Program:
    exit
main ENDP

; -------------------------------------------------------------------
; Procedure: CountSubstring
; Description: Scans a buffer for occurrences of a specific substring.
; Receives: 
;   ESI = Pointer to buffer
;   EDI = Pointer to substring
;   ECX = Size of buffer (bytes)
;   EDX = Length of substring (bytes)
; Returns: 
;   EAX = Total occurrences found
; -------------------------------------------------------------------
CountSubstring PROC
    ; Save registers to preserve their values across the call
    push ebx
    push ecx
    push esi
    push edi
    push edx

    mov ebx, 0           ; Initialize match counter (EBX) to 0

    ; If buffer length is smaller than substring length, return 0
    cmp ecx, edx
    jl CS_End

    ; Calculate outer loop iterations: (Buffer_Size - Substring_Length) + 1
    sub ecx, edx
    inc ecx              ; ECX is now the counter for the outer loop

CS_OuterLoop:
    ; Save current state for the inner loop
    push esi             ; Save current position in buffer
    push edi             ; Save start of substring
    push ecx             ; Save outer loop counter

    mov ecx, edx         ; Set inner loop counter to substring length

CS_InnerLoop:
    mov al, [esi]        ; Get character from buffer
    mov ah, [edi]        ; Get character from substring
    cmp al, ah           ; Compare them
    jne CS_Mismatch      ; If they don't match, break out of inner loop
    
    inc esi              ; Move to next buffer character
    inc edi              ; Move to next substring character
    loop CS_InnerLoop    ; Decrement ECX, jump to CS_InnerLoop if ECX > 0

    ; If the inner loop finishes without jumping to CS_Mismatch, it's a match!
    inc ebx              ; Increment our match counter

CS_Mismatch:
    ; Restore state for the next outer loop iteration
    pop ecx              ; Restore outer loop counter
    pop edi              ; Restore start of substring
    pop esi              ; Restore buffer position
    
    inc esi              ; Advance buffer position by 1 byte for next scan
    loop CS_OuterLoop    ; Decrement outer ECX, loop if > 0

CS_End:
    mov eax, ebx         ; Move final match count into EAX for return

    ; Restore all saved registers
    pop edx
    pop edi
    pop esi
    pop ecx
    pop ebx
    ret
CountSubstring ENDP



MyWriteString PROC
    pushad
    push edx
    INVOKE lstrlenA, edx
    mov ecx, eax
    pop edx
    INVOKE GetStdHandle, -11
    mov stdOutHandle, eax
    INVOKE WriteFile, stdOutHandle, edx, ecx, ADDR bytesWritten, 0
    popad
    ret
MyWriteString ENDP

MyWriteDec PROC
    pushad
    INVOKE wsprintfA, ADDR num_buf, ADDR fmt_dec, eax
    mov edx, OFFSET num_buf
    call MyWriteString
    popad
    ret
MyWriteDec ENDP

MyCrlf PROC
    pushad
    mov edx, OFFSET fmt_nl
    call MyWriteString
    popad
    ret
MyCrlf ENDP

END main

