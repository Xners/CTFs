flag = "szzyfimhyzd"#密文字符串
 
flaglist = []
 
for i in flag:
    flaglist.append(ord(i)-97)

#爆破 
flags = ""
for i in flaglist:
    for j in range(0,26):
        c = (17 * j - 8) % 26
        if(c == i):
            flags += chr(j+97)
print(flags)