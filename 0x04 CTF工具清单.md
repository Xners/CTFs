# 图片分离

1. binwalk -e 原文件名.xxx
2. foremost -T 原文件名.xxx
3. dd if=原文件名.xxx bs=1 skip=9591 of=新文件名.xxx
4. 手工分离

# 破解压缩包密码（zip包、rar包）
1. ZipCenOp.jar
2. rar包伪密码：将0x74后的0x84改成0x80
3. Archpr 明文、字典、爆破攻击密码
4. 脑洞根据提示破密码


# 图片隐写
1. stegsolve
2. lsb.py (github)
3. JPHS(github)
4. 盲水印(github)

# 音频隐写
1. mp3stego
加密 encode -E hidden.txt -P 密码 文件
解密 decode -X -P 密码 文件
2. audacity

# NTFS数据流隐写
1. alternatestreamview

# 进制互转/加解密/编码工具
1. converter
2. ctfcracker

# 流量分析
1. wireshark

# 十六进制分析
1. HsD
2. 010Editor
3. Java Decompiler
4. RouterPassView


