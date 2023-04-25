package Login

import (
	"fmt"
	"github.com/stacktitan/smb/smb"
	"github.com/wintrysec/Taiji/Common"
	"strings"
	"sync"
)

func Smb_Scan(hosts []string, timeout int64, workers int) {
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
				SmbConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["smb"]
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

func SmbConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	//先测试一下空连接，如果可以直接返回结果
	if Anonymous(host) {
		wg.Add(1)
		msg := fmt.Sprintf("[SMB] %v %v", host, "NULL-IPC-Connect")
		res <- msg
		return
	}
	ip := strings.Split(host, ":")[0]
	options := smb.Options{
		Host:        ip,
		Port:        445,
		User:        user,
		Password:    password,
		Domain:      ".",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			wg.Add(1)
			msg := fmt.Sprintf("[SMB] %v %v:%v", host, user, password)
			res <- msg
		} else {
			msg := fmt.Sprintf("[SMB-Crack] %v %v:%v", host, user, password)
			fmt.Println(msg)
			return
		}
	} else {
		return
	}
}

func Anonymous(host string) bool {
	ip := strings.Split(host, ":")[0]
	options := smb.Options{
		Host:        ip,
		Port:        445,
		User:        "Administrator",
		Password:    "",
		Domain:      ".",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			return true
		} else {
			return false
		}
	} else {
		return false
	}
}
