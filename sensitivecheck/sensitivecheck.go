package sensitivecheck

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"fmt"
	"github.com/gogf/gf/encoding/gbinary"
	"io"
	"os"
	"sync/atomic"
	"unicode"
	"unsafe"
)

// TrieTreeNode 字典树节点
type TrieTreeNode struct {
	id    int32                  //节点id
	pId   int32                  //父节点id（如是根节点则-1）
	word  rune                   //当前节点字符（如是根节点则-1）
	next  map[rune]*TrieTreeNode // 该字典树节点的子节点，key:字符
	isEnd bool                   // 该节点是否到达屏蔽词的末尾
}

// 前缀树根
var root *TrieTreeNode

// 要过滤的标点符号Set
var punctuationSet = map[rune]struct{}{
	' ': {}, '　': {}, '!': {}, '！': {}, '"': {}, '＂': {}, '#': {},
	'＃': {}, '$': {}, '＄': {}, '%': {}, '％': {}, '&': {}, '＆': {}, '\'': {}, '＇': {}, '(': {}, '（': {},
	')': {}, '）': {}, '*': {}, '＊': {}, '+': {}, '＋': {}, ',': {}, '，': {}, '-': {}, '－': {}, '.': {},
	'．': {}, '/': {}, '／': {}, ':': {}, '：': {}, ';': {}, '；': {}, '<': {}, '＜': {}, '=': {}, '＝': {},
	'>': {}, '＞': {}, '?': {}, '？': {}, '@': {}, '＠': {}, '[': {}, '［': {}, '\\': {}, '＼': {}, ']': {},
	'］': {}, '^': {}, '＾': {}, '_': {}, '＿': {}, '`': {}, '｀': {}, '{': {}, '｛': {}, '|': {}, '｜': {},
	'}': {}, '｝': {}, '~': {}, '～': {}, '｡': {}, '。': {}, '｢': {}, '「': {}, '｣': {}, '」': {}, '､': {},
	'、': {}, '･': {}, '・': {}, '⟨': {}, '〈': {}, '⟩': {}, '〉': {}, '⟪': {}, '《': {}, '⟫': {}, '》': {},
	'￨': {}, '│': {}, '￥': {}, '…': {}, '—': {}, '【': {}, '】': {}, '‘': {}, '”': {}, '“': {}, '’': {}, '\t': {},
}

// 将全角换成半角(英文字母统一转小写)
var fullwidthToHalfwidthMap = map[rune]rune{
	'Ａ': 'a', 'Ｂ': 'b', 'Ｃ': 'c', 'Ｄ': 'd', 'Ｅ': 'e', 'Ｆ': 'f', 'Ｇ': 'g', 'Ｈ': 'h', 'Ｉ': 'i', 'Ｊ': 'j', 'Ｋ': 'k',
	'Ｌ': 'l', 'Ｍ': 'm', 'Ｎ': 'n', 'Ｏ': 'o', 'Ｐ': 'p', 'Ｑ': 'q', 'Ｒ': 'r', 'Ｓ': 's', 'Ｔ': 't', 'Ｕ': 'u', 'Ｖ': 'v',
	'Ｗ': 'w', 'Ｘ': 'x', 'Ｙ': 'y', 'Ｚ': 'z', 'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
	'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
	'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z', '０': '0', '１': '1', '２': '2',
	'３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
}

// 敏感词源文件名

func getRoot() *TrieTreeNode {
	return (*TrieTreeNode)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&root))))
}

func reloadRoot(newRoot *TrieTreeNode) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&root)), unsafe.Pointer(newRoot))
}

// 初始化前缀树
func Init() {
	//打开敏感词文件
	sourceFile, err := os.Open(getSourceFileName())
	if err != nil {
		fmt.Printf("敏感词检查源文件 %s 打开失败: %s \n", sourceFile.Name(), err.Error())
		return
	}
	defer func(sourceFile *os.File) {
		err = sourceFile.Close()
		if err != nil {
			fmt.Printf("敏感词检查源文件 %s 关闭失败: %s \n", sourceFile.Name(), err.Error())
		}
	}(sourceFile)

	// 获取源文件md5码
	sourceMd5Bytes, err := getMd5Bytes(sourceFile)
	if err != nil {
		fmt.Printf("敏感词源文件 %s  MD5码签名错误: %s \n", sourceFile.Name(), err.Error())
		return
	}
	fmt.Printf("%s MD5 checksum is %x \n", sourceFile.Name(), sourceMd5Bytes)
	_, err = sourceFile.Seek(0, 0)
	if err != nil {
		fmt.Printf("敏感词源文件 %s 移动文件指针归零失败: %s \n", sourceFile.Name(), err.Error())
		return
	}

	//获取备份文件md5码
	//打开备份文件
	cacheFileName := getCacheFileName()
	cacheFile, err := os.Open(cacheFileName)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 打开失败, 重新加载敏感词检测树并保存 %s \n", cacheFileName, err.Error())
		initTreeAndSave(sourceFile, sourceMd5Bytes)
		return
	}
	defer func(cacheFile *os.File) {
		err = cacheFile.Close()
		if err != nil {
			fmt.Printf("敏感词检查缓存文件 %s 关闭失败 %s \n", cacheFileName, err.Error())
		}
	}(cacheFile)

	// 读取文件的前 16 个字节作为MD5码
	cacheMd5Bytes := make([]byte, 16)
	_, err = cacheFile.Read(cacheMd5Bytes)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 读取源文件MD5码失败, 重新加载敏感词检测树并保存 %s \n", cacheFileName, err)
		initTreeAndSave(sourceFile, sourceMd5Bytes)
		return
	}
	if bytes.Compare(sourceMd5Bytes, cacheMd5Bytes) == 0 {
		readFromCacheFile(cacheFile)
	} else {
		fmt.Printf("发现敏感词文件md5码 %x 与缓存文件md5码 %x 不一致，重新加载 \n", sourceMd5Bytes, cacheMd5Bytes)
		initTreeAndSave(sourceFile, sourceMd5Bytes)
	}
}

// 检测并过滤敏感词，将敏感词转换成*号
// @return bool-是否合法 string-过滤后文字
func MsgCheckFilter(sentence string) (bool, string) {
	if getRoot() == nil {
		fmt.Printf("敏感词检测前缀树为空,无法检测敏感词\n")
		return true, sentence
	}
	//将标点符号通过循环进行过滤
	sentenceCopy := []rune(sentence)
	words := filterByLoop(sentence)
	wordLength := len(words)
	checked := true
	for i := 0; i < wordLength; i++ {
		if words[i] == ' ' {
			continue
		}
		pointer := getRoot()
		for j, word := range words[i:wordLength] {
			if word == ' ' {
				continue
			}
			if value, isMapContains := pointer.next[word]; isMapContains {
				pointer = value
				if pointer.isEnd {
					fmt.Printf("检测到敏感词输入,玩家输入内容:%s, 命中内容:%s\n", sentence, string(words[i:i+j+1]))
					for k := i; k <= i+j; k++ {
						sentenceCopy[k] = '*'
					}
					checked = false
					break
				}
			} else {
				break
			}
		}
	}
	return checked, string(sentenceCopy)
}

// 检测输入的内容是否包含敏感词
func MsgCheck(sentence string) bool {
	if getRoot() == nil {
		fmt.Printf("敏感词检测前缀树根为空，无法检测敏感词\n")
		return true
	}
	//将标点符号通过循环进行过滤
	words := filterByLoop(sentence)
	wordLength := len(words)
	for i := 0; i < wordLength; i++ {
		if words[i] == ' ' {
			continue
		}
		pointer := getRoot()
		for j, word := range words[i:wordLength] {
			if word == ' ' {
				continue
			}
			if value, isMapContains := pointer.next[word]; isMapContains {
				pointer = value
				if pointer.isEnd {
					fmt.Printf("检测到敏感词输入,玩家输入内容:%s, 命中内容:%s\n", sentence, string(words[i:i+j+1]))
					return false
				}
			} else {
				break
			}
		}
	}
	return true
}

// 创建并保存敏感词检测树
func initTreeAndSave(sourceFile *os.File, fileMd5Bytes []byte) {
	// 用于存入文件的树节点列表
	nodeList := make([]*TrieTreeNode, 0, 0)
	// 创建前缀树根
	var id int32 = 0
	newRoot := &TrieTreeNode{id, -1, -1, make(map[rune]*TrieTreeNode), false}
	nodeList = append(nodeList, newRoot)
	reader := bufio.NewReader(sourceFile)
	//读取敏感词，构造前缀树
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		//读取敏感词
		word := []rune(string(line))
		p := newRoot
		length := len(word)
		for key, char := range word {
			//查找树节点是否存在，如不存在则创建一个节点
			val, isMapContains := p.next[char]
			if isMapContains {
				p = val
				if p.isEnd { //如果遍历到此节点时已经是某个敏感词的结束节点，则不需要继续构建后续节点了
					break
				}
			} else {
				id = id + 1
				newNode := &TrieTreeNode{id, p.id, char, make(map[rune]*TrieTreeNode), false}
				//如找到词尾，则该节点为敏感词结束
				if key == length-1 {
					newNode.isEnd = true
				}
				nodeList = append(nodeList, newNode)
				p.next[char] = newNode
				p = newNode
			}

		}
	}
	reloadRoot(newRoot)
	fmt.Printf("从源文件 %s 中读取敏感词成功\n", sourceFile.Name())
	//保存树结构到缓存文件
	saveCacheToFile(fileMd5Bytes, nodeList)
}

// 获取敏感词源文件名称
func getSourceFileName() string {
	return "sensitive.txt"
}

// 自定义缓存文件名称
func getCacheFileName() string {
	return "sensitiveCache.bin"
}

// 保存树结构到缓存文件
func saveCacheToFile(fileMd5Bytes []byte, nodeList []*TrieTreeNode) {
	cacheFileName := getCacheFileName()
	//创建存储文件，写入
	cacheFile, err := os.Create(cacheFileName)
	if err != nil {
		fmt.Printf("Error creating sourceFile: %s\n", err)
		return
	}
	defer cacheFile.Close()
	//保存源文件md5码
	_, err = cacheFile.Write([]byte(fileMd5Bytes))
	if err != nil {
		fmt.Printf("Error writing MD5: %s\n", err)
		return
	}
	//保存列表长度
	lengthByte := gbinary.EncodeInt32(int32(len(nodeList)))
	_, err = cacheFile.Write(lengthByte)
	if err != nil {
		fmt.Printf("写入树节点长度失败: %s\n", err)
		return
	}
	//将树节点依次编码后写入文件
	nodeListLength := len(nodeList)
	for i := 0; i < nodeListLength; i++ {
		node := *nodeList[i]
		_, err = cacheFile.Write(node.encodeNode())
		if err != nil {
			fmt.Printf("写入树节点失败: %s \n", err)
			return
		}
	}
	fmt.Printf("写入树节点成功\n")
}

// 从缓存文件中载入敏感词树
func readFromCacheFile(cacheFile *os.File) {
	var loadedData *TrieTreeNode
	//跳过存储MD5码的16个字节
	_, err := cacheFile.Seek(16, 0)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 移动文件读取指针失败:%s\n", cacheFile.Name(), err.Error())
		return
	}
	// 读取树节点个数, 用int32存储, 4个字节
	lengthByte := make([]byte, 4)
	_, err = cacheFile.Read(lengthByte)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 移动文件读取指针失败:%s\n", cacheFile.Name(), err.Error())
		return
	}
	nodeLength := gbinary.DecodeToInt32(lengthByte)
	//开始读取树节点
	_, err = cacheFile.Seek(20, 0)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 移动文件读取指针失败:%s\n", cacheFile.Name(), err.Error())
		return
	}
	// 一个树节点存储结构包含3个int32和1个boolm, 3*4+1=13
	byteArray := make([]byte, 13*nodeLength)
	nodeList := make([]TrieTreeNode, nodeLength)
	_, err = cacheFile.Read(byteArray)
	if err != nil {
		fmt.Printf("敏感词检查缓存文件 %s 移动文件读取指针失败:%s\n", cacheFile.Name(), err.Error())
		return
	}
	for i := int32(0); i < nodeLength; i++ {
		nodeList[i] = decodeNode(byteArray[i*13 : (i+1)*13])
	}

	loadedData = decodeToSensitiveTree(nodeList)

	if err != nil {
		fmt.Printf("Error decoding file: %s \n", err)
		return
	}
	reloadRoot(loadedData)
	fmt.Printf("从缓存文件 %s 中读取敏感词文件 成功\n", cacheFile.Name())
}

func decodeToSensitiveTree(nodeList []TrieTreeNode) *TrieTreeNode {
	length := len(nodeList)
	nodeRecord := make([]*TrieTreeNode, length, length)
	for i := 0; i < length; i++ {
		newTrieTreeNode := &nodeList[i]
		nodeRecord[newTrieTreeNode.id] = newTrieTreeNode
		if newTrieTreeNode.pId == -1 {
			continue
		}
		nodeRecord[newTrieTreeNode.pId].next[newTrieTreeNode.word] = newTrieTreeNode
	}
	return nodeRecord[int32(0)]
}

// 通过循环进行过滤特殊标点符号
func filterByLoop(originSentence string) []rune {
	sentenceRune := make([]rune, 0, 0)
	originWords := []rune(originSentence)
	for _, originWord := range originWords {
		//如果是标点符号则跳过，置为空格
		if _, isPunctuation := punctuationSet[originWord]; isPunctuation {
			originWord = ' '
		}
		//如果是全角英文和数组，转成半角
		if halfwidthChar, isFullWidth := fullwidthToHalfwidthMap[originWord]; isFullWidth {
			originWord = halfwidthChar
		}
		// 如果是大写字母，统一转成小写
		if unicode.IsUpper(originWord) {
			originWord = unicode.ToLower(originWord)
		}

		sentenceRune = append(sentenceRune, originWord)
	}
	return sentenceRune
}

func getMd5Bytes(file *os.File) ([]byte, error) {
	hash := md5.New()
	_, err := io.Copy(hash, file)
	if err != nil {
		panic(err)
	}
	md5String := hash.Sum(nil)
	return md5String, err
}

func (node TrieTreeNode) encodeNode() []byte {
	res := make([]byte, 13)
	idBytes := gbinary.EncodeInt32(node.id)
	i := 0
	for _, theByte := range idBytes {
		res[i] = theByte
		i++
	}
	idBytes = gbinary.EncodeInt32(node.pId)

	for _, theByte := range idBytes {
		res[i] = theByte
		i++
	}
	idBytes = gbinary.EncodeInt32(node.word)
	for _, theByte := range idBytes {
		res[i] = theByte
		i++
	}
	idBytes = gbinary.EncodeBool(node.isEnd)
	for _, theByte := range idBytes {
		res[i] = theByte
		i++
	}
	return res
}

func decodeNode(bytes []byte) TrieTreeNode {
	res := bytes[0:4]
	id := gbinary.DecodeToInt32(res)
	res = bytes[4:8]
	pId := gbinary.DecodeToInt32(res)
	res = bytes[8:12]
	word := gbinary.DecodeToInt32(res)
	res = bytes[12:13]
	isEnd := gbinary.DecodeToBool(res)
	return TrieTreeNode{id, pId, word, make(map[rune]*TrieTreeNode), isEnd}
}
