
## Linux系统目录结构
```
/bin：	存放最常用命令； 
/boot：	启动Linux的核心文件； 
/dev：	设备文件； 
/etc：	存放各种配置文件； 
/home：	用户主目录,默认情况下用户的根目录都保存在其下； 
/lib：	系统最基本的动态链接共享库； 
/mnt：	一般是空的，用来临时挂载别的文件系统； 
/proc：	虚拟目录，是内存的映射； 
/sbin：	系统管理员命令存放目录； 
/usr：	最大的目录，存放应用程序和文件；
/opt:   应用程安装目录,如数据库,用户自身的应用程序; 
/usr/X11R6：X-Window目录； 
/usr/src：	Linux源代码； 
/usr/include：系统头文件； 
/usr/lib：	存放常用动态链接共享库、静态档案库； 
/usr/bin、/usr/sbin：这是对/bin、/sbin的一个补充
```
## Linux常见命令

1. ls
- ls -a  -- 显示隐藏文件
- ls -r -- 反序显示
- ls -l -- 显示详细信息
- ls -R -- 递归地显示目录中内容
- ls --help | more
```
root@kali:~# cd /tmp
root@kali:/tmp# ls -R
.:
liuliangbuhuo.py  lost+found  usbdata.txt  usb.pcapng

./lost+found:
```

```
root@kali:/tmp# ls -dl /bin
drwxr-xr-x 2 root root 4096 Nov  7 07:12 /bin
root@kali:/tmp# ls -l /bin
total 12488
-rwxr-xr-x 1 root root 1168776 Apr 18  2019 bash
-rwxr-xr-x 3 root root   38984 Sep  5  2019 bunzip2
-rwxr-xr-x 1 root root  707288 Apr  1  2019 busybox

```


```
root@kali:/tmp# ls -i /root
 139611 0425_misc_2.py                137353 -h
 139610 0425_misc.py                  137366 help
 136453 115.php                       136366 index.php
 136433 1.dll                         137343 linux_amd64
 134030 1.hta                         136276 mm.cmd
 136524 1.txt                         134034 msfinstall

```
2. cd命令
- cd ..  更换目录回到上一级目录
- cd .   更换到当前目录
- cd ~   更换目录到当前用户的个人宿主目录
- cd /etc/vsftpd/  更换到/etc/vsftpd目录
- cd /   更换目录到根目录

3. pwd -- 显示当前工作目录的绝对路径

4. clear -- 清除屏幕上的信息

5. man -- man实际上就是查看命令用法的help，学习任何一种UNIX类的操作系统最重要的就是学会使用man这个辅助命令。man是manual(手册)的缩写字，它的说明非常的详细，建议记得一些基本用法就可以了
man ls

6. mkdir 
```
root@kali:/tmp# mkdir -m 777 /usr/tmp
root@kali:/tmp# cd /usr/tmp
root@kali:/usr/tmp# ls -dl
drwxrwxrwx 2 root root 4096 Apr 26 22:10 .
```

7. rmdir -- 删除一个或多个空目录或空子目录，要求此用户在当前目录上具有写权限
```
rmdir /usr/tmp
```

8. rm
```
root@kali:/usr# cd /tmp
root@kali:/tmp# ls
liuliangbuhuo.py  lost+found  usbdata.txt  usb.pcapng
root@kali:/tmp# rm usbdata.txt 
root@kali:/tmp# ls
liuliangbuhuo.py  lost+found  usb.pcapng
root@kali:/tmp# rm -f -i usb.pcapng 
rm: remove regular file 'usb.pcapng'? Y
root@kali:/tmp# ls
liuliangbuhuo.py  lost+found
```
9. touch -- 修改文件的系统时间属性，如果文件不存在则创建一个新的文件

10. ln -- 语法：ln [参数选项]  源文件  链接文件
	说明：创建链接文件，分为硬链接和软链接，加-s参数为创建软链接
```
root@kali:/mnt/hgfs/Downloads/test# ln -s /mnt/hgfs/Downloads/test /tmp/ii
root@kali:/mnt/hgfs/Downloads/test# ls /tmp
ii  oo  q  q.txt
root@kali:/mnt/hgfs/Downloads/test# ls -al /tmp
total 5
drwxr-xr-x  2 root root 1024 Apr 26 22:44 .
drwxr-xr-x 25 root root 4096 Nov  7 07:13 ..
lrwxrwxrwx  1 root root   24 Apr 26 22:44 ii -> /mnt/hgfs/Downloads/test
lrwxrwxrwx  1 root root    7 Apr 26 22:41 oo -> exp1.py
lrwxrwxrwx  1 root root    5 Apr 26 22:26 q -> q.txt
-rw-r--r--  1 root root    0 Apr 26 22:25 q.txt
root@kali:/mnt/hgfs/Downloads/test# cd /tmp/ii
root@kali:/tmp/ii# ls
core  exp1.py  libc.so.6  peda-session-test.txt  test  test.i64
```

11. cp -- cp [参数选项] 源文件或目录 目标文件或目录 
```
root@kali:/# cp -R /mnt/hgfs/Downloads/test /tmp/test
cp: error writing '/tmp/test/libc.so.6': No space left on device
cp: error writing '/tmp/test/test': No space left on device
cp: error writing '/tmp/test/test.i64': No space left on device
root@kali:/# ls /tmp/test
core  exp1.py  libc.so.6  peda-session-test.txt  test  test.i64
```

12. mv -- mv [参数选项] 源文件或目录 目标文件或目录 
13. chmode 
- -- 语法1：chmod [options] [who] opcode permission file…
	语法2：chmod [options] [n1]n2n3n4  file…
	说明：改变文件或目录的权限模式

```
第一种：chmod –R u=rwx,g=rw,o=rx  /home/test
第二种：chmod -R 765  /home/test
```

- -- chmod [-cfvR] [--help] [--version] mode file...
```
-c : 若该文件权限确实已经更改，才显示其更改动作
-f : 若该文件权限无法被更改也不要显示错误讯息
-v : 显示权限变更的详细资料
-R : 对目前目录下的所有文件与子目录进行相同的权限变更(即以递回的方式逐个变更)
-mode=>[ugoa...][[+-=][rwxX]...][,...]

-u 表示该文件的拥有者，g 表示与该文件的拥有者属于同一个群体(group)者，o 表示其他以外的人，a 表示这三者皆是。
- + 表示增加权限、- 表示取消权限、= 表示唯一设定权限。
-r 表示可读取，w 表示可写入，x 表示可执行，X 表示只有当该文件是个子目录或者该文件已经被设定过为可执行。
```
```
chmod ugo+r file1.txt  将文件 file1.txt 设为所有人皆可读取 
chmod a+r file1.txt 将文件 file1.txt 设为所有人皆可读取
若用chmod 4755filename可使此程序具有root的权限
chmod ug=rwx,o=x file
chmod -R a+r * 将目前目录下的所有文件与子目录皆设为任何人可读取
```
14. chown 
- chown [-cfhvR] [--help] [--version] user[:group] file...
```
user : 新的文件拥有者的使用者 ID
group : 新的文件拥有者的使用者组(group)
-c : 显示更改的部分的信息
-f : 忽略错误信息
-h :修复符号链接
-v : 显示详细的处理信息
-R : 处理指定目录以及其子目录下的所有文件
```
```
chown runoob:runoobgroup file1.txt 将文件 file1.txt 的拥有者设为 runoob，群体的使用者 runoobgroup
chown -R runoob:runoobgroup * 将目前目录下的所有文件与子目录的拥有者皆设为 runoob，群体的使用者 runoobgroup
```

15. chgrp
- chgrp [options] newgroup  file…
```
chgrp  root  /home/test/test1 将test1文件改成root组
```

16.cat|more|less|head|tail

```
root@kali:/tmp/test# cat -E -n exp1.py
     1	from pwn import *$
     2	$
     3	$
     4	p = process("./test")$
     5	$
     6	pause()$
```
- cat 命令把档案串连后传到基本输出(或加 >重定向到另一个文件）
```
root@kali:/tmp/test# cat exp1.py > exp2.py
root@kali:/tmp/test# ls exp
exp1.py  exp2.py 
```

16. find命令

- 语法：find [搜索路径] [参数选项] [匹配表达式] 
- 功能：在指定的搜索路径下搜索指定的目录或文件
```
-name 字符：查找的包包“字符”的文件和目录。
-perm 模式: 匹配所有符合指定数值模式值的文件。
-size n[c]：匹配大小为n个block的文件名，c:以字节为单位
-user 用户名：搜索所有属主为用户名的文件。
-group 组名：搜索所有属主为组名的文件。
-atime n：搜索在n天前访问过的文件。
-mtime n：搜索在n天前状态修改过的文件。
-ctime n：搜索在n天前修改过的文件。
-exec 命令 {} \;  ：对每个匹配的文件执行该命令，标志{}用于指定命令执行时文件名出现的地方，命令必须终止于符号“{}\;”
```
```
find / -size 0 –exec rm –rf {} \; 查找所有空文件并将其删除
find . -name "*.c" 目前目录及其子目录下所有延伸档名是 c 的文件列出来
find /var/log -type f -mtime +7 -ok rm {} \; 查找/var/log目录中更改时间在7日以前的普通文件，并在删除之前询问它们
find . -type f -perm 644 -exec ls -l {} \; 查找前目录中文件属主具有读、写权限，并且文件所属组的用户和其他用户具有读权限的文件
```

17. grep 命令
- 语法：grep [参数选项] [-e PATTERN | -f - FILE] [FILE...]
- 说明：在文件中搜索匹配的行并输出，一般用来过滤先前结果而避免显示太多不必要的信息。
- 'egrep' means 'grep -E'.  'fgrep' means 'grep -F'
```
egrep -Rwi --color 'warning|error' /home/logs/ 递归查找\忽略大小写\高亮\完全匹配关键词\多文本\多文件
```
18. strings命令
- 打印文件，包括可执行文件
```
strings命令很简单， 看起来好像没什么， 但实际有很多用途。 下面， 我来举一个例子。  在大型的软件开发中， 假设有100个.c/.cpp文件， 这个.cpp文件最终生成10个.so库， 那么怎样才能快速知道某个.c/.cpp文件编译到那个.so库中去了呢？ 当然， 你可能要说， 看makefile不就知道了。 对， 看makefile肯定可以， 但如下方法更好， 直接用命令：
strings -f "*.so" | grep "xxxxxx"

如果还不明白， 那就就以上面的小程序为例为说明， 不过， 此处我们考虑所有的文件， 如下：

[taoge@localhost learn_c]$ strings -f * | grep "my dear"
a.out: oh, my dear, c is %d
test.c: 	printf("oh, my dear, c is %d\n", c);
[taoge@localhost learn_c]$ 
可以看到， 源文件test.c和可执行文件中皆有"my dear"串， 一下子就找到了对应的文件，清楚了吧。如果某.c/.cpp文件编译进了.so库， 那么，strings -f * | grep "my dear"必定可以找到对应的.so文件， 其中"my dear"为该.c/.cpp文件中的某个日志串（比如以printf为打印）。

root@kali:/tmp/test# strings -f ./libc.so.6  | grep GLIBC
./libc.so.6: GLIBC_2.2.5
./libc.so.6: GLIBC_2.2.6
./libc.so.6: GLIBC_2.3
./libc.so.6: GLIBC_2.3.2
./libc.so.6: GLIBC_2.3.3
./libc.so.6: GLIBC_2.3.4

```
19. file|who|w|whoami|finger|
20. su|sudo|passwd|gpasswd
21. ps|kill|killall
22. tar|gzip|bzip
23. vim
