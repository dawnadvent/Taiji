package Common

import (
	"bufio"
	"fmt"
	"os"
)

// 日志存储和输出,如要入数据库也可以在这里操作
func Savelog(msg string) {
	text := fmt.Sprintf("%s\n", msg)

	//根据命令行给的参数选择是否保存日志到文件或者只到系统标准输出
	if Log {
		// 打开文件以进行写入
		file, err := os.OpenFile(Logpath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Printf("Open File failed for %v. Error: %s", Logpath, err.Error())
		}
		defer file.Close()

		// 创建一个新的 writer 对象
		writer := bufio.NewWriter(file)

		// 写入字符串
		_, err = writer.WriteString(text)
		if err != nil {
			fmt.Printf("Writer failed %v. Error: %s", Logpath, err.Error())
		}

		// 将缓冲区中的数据刷新到磁盘中
		err = writer.Flush()
		if err != nil {
			fmt.Println(err)
		}
	}
	//默认只将结果输出到标准输出
	fmt.Println(msg)
}
