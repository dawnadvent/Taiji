package Login

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"net"
	"strings"
	"sync"
	"time"
)

func Redis_Scan(hosts []string, timeout int64, workers int) {
	var wg sync.WaitGroup
	Addrs := make(chan Addr, len(hosts))
	results := make(chan string, len(hosts))

	//接收结果
	go func() {
		for found := range results {
			//输出结果、日志、入库
			Common.Savelog(found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				RedisConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["redis"]
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

// RedisConnect 建立连接
func RedisConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
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
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", password)))
	if err != nil {
		return
	}
	reply, err := readreply(conn)
	if err != nil {
		return
	}
	//fmt.Println(host,password)
	//fmt.Println(reply)
	if strings.Contains(reply, "ERR Client sent AUTH, but no password is set") {
		_, err = conn.Write([]byte("info\r\n"))
		if err != nil {
			return
		}
		reply, err := readreply(conn)
		if err != nil {
			return
		}
		if strings.Contains(reply, "redis_version") {
			wg.Add(1)
			msg := fmt.Sprintf("[Redis] %v %v", host, "unauth access")
			res <- msg
		}
	} else if strings.Contains(reply, "+OK") {
		wg.Add(1)
		msg := fmt.Sprintf("[Redis] %v %v", host, password)
		res <- msg
	} else {
		msg := fmt.Sprintf("[Redis-Crack] %v %v", host, password)
		fmt.Println(msg)
		return
	}
}

// 读取响应
func readreply(conn net.Conn) (result string, err error) {
	size := 5 * 1024
	buf := make([]byte, size)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result += string(buf[0:count])
		if count < size {
			break
		}
	}
	return result, err
}
