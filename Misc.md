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

