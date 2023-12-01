# Golang 敏感词检测模块
这是一款敏感词检测模块，判断句子中是否包含配置的敏感词，且支持**直接判定是否存在敏感词** 和 **将敏感词过滤为*号** 两种判定方式。

支持从缓存中读取敏感词前缀树。在每一次从敏感词源文件中逐行读取敏感词，并构建敏感词前缀树后，将敏感词的树节点转为二进制数据，存入文件中，同时记录源文件的MD5码。

下次再次调用`Init()`函数时，当缓存文件存在时，校验缓存文件记录的源文件MD5码与当前源文件MD5码是否一致，如果一致，则敏感词文件未被修改过，此时从缓存文件读取效率更高。

本模块不建议用户使用`go get ...`进行安装，而是将`sensitivecheck`文件夹引入自己的项目中，然后在调用`MsgCheck`或`MsgCheckFilter`前保证初始化过前缀树，即调用`Init()`方法。

## 功能测试
1. checkout本项目，运行`main.go`中的main函数，你将看到控制台输出结果。
```
敏感词检查缓存文件 sensitiveCache.bin 打开失败, 重新加载敏感词检测树并保存 open sensitiveCache.bin: The system cannot find the file specified. 
从源文件 sensitive.txt 中读取敏感词成功
写入树节点成功
使用判断敏感词是否存在，来检测内容：科比
检测到敏感词输入,玩家输入内容:科比, 命中内容:科比
结果为:  false
使用过滤敏感词为*号，来检测内容：科比
检测到敏感词输入,玩家输入内容:我是科比, 命中内容:科比
结果为:  false 我是**
使用判断敏感词是否存在，来检测内容：你好
结果为:  true
使用过滤敏感词为*号，来检测内容：你好
结果为:  true 你好
```
2. 可以看到文件夹目录下出现`sensitiveCache.bin`文件，这个文件是敏感词树的缓存文件。再次运行main函数时，系统会从缓存文件中读取敏感词，将输出：
```
sensitive.txt MD5 checksum is 2cbc81470cc9949e55380b735e2e84af 
从缓存文件 sensitiveCache.bin 中读取敏感词文件 成功
使用判断敏感词是否存在，来检测内容：科比
检测到敏感词输入,玩家输入内容:科比, 命中内容:科比
结果为:  false
使用过滤敏感词为*号，来检测内容：科比
检测到敏感词输入,玩家输入内容:我是科比, 命中内容:科比
结果为:  false 我是**
使用判断敏感词是否存在，来检测内容：你好
结果为:  true
使用过滤敏感词为*号，来检测内容：你好
结果为:  true 你好
```
3. 你可以修改sensitive.txt中的敏感词，注意一行一个敏感词。
```
詹姆斯
科比
```

## 建议使用方法
1. 将`sensitivecheck`整个文件夹复制到你的golang项目中，作为一个包进行使用
2. 在你项目中启动初始化的地方调用`sensitivecheck`包下的`Init()`函数
3. 在你项目中需要检测敏感词的地方，使用`sensitivecheck.MsgCheck()`或`sensitivecheck.MsgCheckFilter()`函数，进行检测输入的内容是否包含敏感词。
4. 你可以自由修改`sensitivecheck.go`中`getSourceFileName()`和`getCacheFileName()`的内容，自定义存储的路径位置。

## 项目细节介绍
本项目使用字典前缀树算法实现。

使⽤TrieTree字典前缀树，将敏感词逐条遍历，构造⼀棵字典树。然后再将要检测的句⼦，遍历句⼦中 的每⼀个字，以这个字为开头到末尾，作为要检测的字符串，与字典树进⾏匹配。如找到字典树节点为敏感词结束节点，则命中敏感词。
参考：https://zhuanlan.zhihu.com/p/451564063
