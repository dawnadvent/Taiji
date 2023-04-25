package Plugs

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"net"
	"sync"
	"time"
)

func PortScan(ips []string, ports string, timeout int64, workers int) []string {
	var AliveHost []string
	var wg sync.WaitGroup
	Sports := Common.ParsePort(ports)
	Addrs := make(chan Addr, len(ips)*len(Sports))
	results := make(chan string, len(ips)*len(Sports))

	//接收结果
	go func() {
		for found := range results {
			AliveHost = append(AliveHost, found)
			//输出结果、日志、入库
			Common.Savelog(found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range Sports {
		for _, ip := range ips {
			wg.Add(1)
			Addrs <- Addr{ip, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	return AliveHost
}

func PortConnect(addr Addr, res chan<- string, timeout int64, wg *sync.WaitGroup) {
	ip, port := addr.ip, addr.port
	conn, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%v", ip, port), time.Duration(timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		wg.Add(1)
		result := fmt.Sprintf("%s:%v", ip, port)
		res <- result
	}
}
