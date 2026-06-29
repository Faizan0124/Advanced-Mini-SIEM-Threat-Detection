import re

with open("Mini_SIEM.asm", "r") as f:
    code = f.read()

# Remove the previously added imports
imports_to_remove = """
includelib kernel32.lib
includelib user32.lib
WriteFile PROTO STDCALL :DWORD, :PTR BYTE, :DWORD, :PTR DWORD, :DWORD
GetStdHandle PROTO STDCALL :DWORD
lstrlenA PROTO STDCALL :PTR BYTE
wsprintfA PROTO C :PTR BYTE, :PTR BYTE, :VARARG
"""
code = code.replace(imports_to_remove, "")

# Add ONLY what's missing, e.g. wsprintfA PROTO C :VARARG
imports = """
includelib user32.lib
wsprintfA PROTO C :PTR BYTE, :PTR BYTE, :VARARG
lstrlenA PROTO STDCALL :PTR BYTE
"""
# Make sure we don't have multiple imports
code = code.replace("INCLUDE Irvine32.inc", "INCLUDE Irvine32.inc\n" + imports)

with open("Mini_SIEM.asm", "w") as f:
    f.write(code)

print("Fixed imports in Mini_SIEM.asm!")
