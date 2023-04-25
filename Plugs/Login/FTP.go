package Login

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/wintrysec/Taiji/Common"
	"strings"
	"sync"
	"time"
)

func Ftp_Scan(hosts []string, timeout int64, workers int) {
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
				FtpConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["ftp"]
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

func FtpConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	conn, err := ftp.Dial(host, ftp.DialWithTimeout(time.Duration(timeout)*time.Second))
	if err != nil {
		return
	}
	defer conn.Quit()
	err = conn.Login("anonymous", "anonymous")
	if err == nil {
		defer conn.Logout()
		wg.Add(1)
		msg := fmt.Sprintf("[FTP] %v %v:%v", host, user, password)
		res <- msg
		return
	}

	err = conn.Login(user, password)
	if err == nil {
		defer conn.Logout()
		wg.Add(1)
		msg := fmt.Sprintf("[FTP] %v %v:%v", host, user, password)
		res <- msg
	} else {
		msg := fmt.Sprintf("[FTP-Crack] %v %v:%v", host, user, password)
		fmt.Println(msg)
		return
	}
}
