package Login

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"net"
	"strings"
	"sync"
	"time"
)

func Mongo_Scan(hosts []string, timeout int64, workers int) {
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
				MongoConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["mongodb"]
	}
	for _, host := range hosts {
		for _, acount := range Dict {
			user := strings.Split(acount, ":")[0]
			pass := strings.Split(acount, ":")[1]
			wg.Add(1)
			Addrs <- Addr{host, user, pass}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
}

func MongoConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	senddata := []byte{58, 0, 0, 0, 167, 65, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 255, 255, 255, 255, 19, 0, 0, 0, 16, 105, 115, 109, 97, 115, 116, 101, 114, 0, 1, 0, 0, 0, 0}
	conn, err := net.DialTimeout("tcp", host, time.Duration(timeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		return
	}
	_, err = conn.Write(senddata)
	if err != nil {
		return
	}
	buf := make([]byte, 1024)
	count, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	text := string(buf[0:count])
	if strings.Contains(text, "ismaster") {
		wg.Add(1)
		msg := fmt.Sprintf("[MongoDB] %v unauth access", host)
		res <- msg
	}
}
