package main

import (
	"fmt"
	"sensitive-check/sensitivecheck"
)

func main() {
	// 初始化敏感词检测树
	sensitivecheck.Init()

	fmt.Println("使用判断敏感词是否存在，来检测内容：科比")
	res := sensitivecheck.MsgCheck("科比")
	fmt.Println("结果为: ", res)

	fmt.Println("使用过滤敏感词为*号，来检测内容：科比")
	res, filtered := sensitivecheck.MsgCheckFilter("我是科比")
	fmt.Println("结果为: ", res, filtered)

	fmt.Println("使用判断敏感词是否存在，来检测内容：你好")
	res = sensitivecheck.MsgCheck("你好")
	fmt.Println("结果为: ", res)

	fmt.Println("使用过滤敏感词为*号，来检测内容：你好")
	res, filtered = sensitivecheck.MsgCheckFilter("你好")
	fmt.Println("结果为: ", res, filtered)
}
