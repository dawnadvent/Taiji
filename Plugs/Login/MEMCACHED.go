package Login

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"net"
	"strings"
	"sync"
	"time"
)

func Memcached_Scan(hosts []string, timeout int64, workers int) {
	var wg sync.WaitGroup
	Addrs := make(chan Addr, len(hosts))
	results := make(chan string, len(hosts))

	//接收结果
	go func() {
		for found := range results {
			Common.Savelog(found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				MemcachedConnect(addr.host, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	for _, host := range hosts {
		wg.Add(1)
		Addrs <- Addr{host, "", ""}
	}
	wg.Wait()
	close(Addrs)
	close(results)
}

func MemcachedConnect(host string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	client, err := net.DialTimeout("tcp", host, time.Duration(timeout)*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n"))
			if err == nil {
				rev := make([]byte, 1024)
				n, err := client.Read(rev)
				if err == nil {
					if strings.Contains(string(rev[:n]), "STAT") {
						wg.Add(1)
						msg := fmt.Sprintf("[Memcached] %v unauth access", host)
						res <- msg
					}
				} else {
					return
				}
			}
		}
	}
}
