package main

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"github.com/wintrysec/Taiji/Plugs"
	"time"
)

func main() {
	Common.Banner()
	//解析命令行指定的参数
	var Info Common.HostInfo
	Common.Flag(&Info)

	//开始扫描,下发任务并计时
	start := time.Now()
	Plugs.Scan(Info) //交给扫描查价去分配任务
	end := time.Since(start)
	msg := fmt.Sprintf("\nAll Scan End, Spend Time, %v", end)
	Common.Savelog(msg)
}
