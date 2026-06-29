with open("Mini_SIEM.asm", "r") as f:
    code = f.read()

code = code.replace("INVOKE lstrlenA, edx", "push edx\n    INVOKE lstrlenA, edx\n    mov ecx, eax\n    pop edx\n")
# Wait, my previous code had `mov ecx, eax` right after. Let's be careful.
# Original:
#    INVOKE lstrlenA, edx
#    mov ecx, eax
#    INVOKE GetStdHandle, -11

# Let's just rewrite the PROC completely using regex
import re
new_proc = """MyWriteString PROC
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
MyWriteString ENDP"""

code = re.sub(r'MyWriteString PROC.*?MyWriteString ENDP', new_proc, code, flags=re.DOTALL)

with open("Mini_SIEM.asm", "w") as f:
    f.write(code)

print("Fixed MyWriteString!")
