package Plugs

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// 目标地址结构体
type Addr struct {
	ip   string
	port int
}

func IcmpScan(ips []string, workers int) []string {
	var AliveIPS []string
	var wg sync.WaitGroup
	Addrs := make(chan Addr, len(ips))
	results := make(chan string, len(ips))

	//接收结果
	go func() {
		for found := range results {
			AliveIPS = append(AliveIPS, found)
			Common.Savelog(fmt.Sprintf("%v\tHost is alive", found))
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				System_Ping(addr.ip, results, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, host := range ips {
		wg.Add(1)
		Addrs <- Addr{host, 0}
	}

	//等待所有协程结束
	wg.Wait()

	//关闭通信通道
	close(Addrs)
	close(results)
	return AliveIPS
}

func System_Ping(ip string, res chan<- string, wg *sync.WaitGroup) {
	system_Type := runtime.GOOS
	cmd := exec.Command("ping", ip, "-n", "1", "-w", "3")
	if system_Type == "linux" {
		cmd = exec.Command("ping", ip, "-c", "1", "-W", "3")
	}
	err := cmd.Run()
	if err == nil {
		wg.Add(1) //结果加一，计时器加一
		res <- ip
	}
}

// 提取存活C段
func GetAliveC(AliveAddress []string) []string {
	var Alivec []string
	for _, ip := range AliveAddress {
		IpRange := strings.Join(strings.Split(ip, ".")[0:3], ".")
		IpRange = IpRange + ".1/24"
		if !in(IpRange, Alivec) {
			Alivec = append(Alivec, IpRange)
		}
	}
	return Alivec
}

// 判断某字符串是否在字符串数组中
func in(target string, str_array []string) bool {
	for _, element := range str_array {
		if target == element {
			return true
		}
	}
	return false
}
