import re

with open("Mini_SIEM.asm", "r") as f:
    code = f.read()

# We already patched it once, so let's revert back or just patch the patched version.
# Let's clean it up by reading original if we can? No, we patched in-place.
# I will just replace the previously added `includelib msvcrt.lib` and `printf PROTO` with nothing.
code = code.replace("includelib msvcrt.lib", "")
code = code.replace("printf PROTO C, :PTR BYTE, :VARARG", "")

# And replace the previously added procs with new ones.
# Find the start of MyWriteString PROC and remove everything until END main
start_idx = code.find("MyWriteString PROC")
if start_idx != -1:
    end_idx = code.find("END main", start_idx)
    if end_idx != -1:
        code = code[:start_idx] + "END main\n"

# Add the new imports at the top
imports = """
includelib kernel32.lib
includelib user32.lib
WriteFile PROTO STDCALL :DWORD, :PTR BYTE, :DWORD, :PTR DWORD, :DWORD
GetStdHandle PROTO STDCALL :DWORD
lstrlenA PROTO STDCALL :PTR BYTE
wsprintfA PROTO C :PTR BYTE, :PTR BYTE, :VARARG
"""
code = code.replace("INCLUDE Irvine32.inc", "INCLUDE Irvine32.inc\n" + imports)

# Add variables to .data
data_vars = """
stdOutHandle DWORD ?
bytesWritten DWORD ?
num_buf BYTE 20 DUP(0)
"""
code = code.replace(".data", ".data\n" + data_vars)

# Add the new Procs
procs = """
MyWriteString PROC
    pushad
    INVOKE lstrlenA, edx
    mov ecx, eax
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
"""
code = code.replace("END main", procs)

with open("Mini_SIEM.asm", "w") as f:
    f.write(code)

print("Repatched Mini_SIEM.asm for Win32 API!")
