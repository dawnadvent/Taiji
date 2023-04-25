package Login

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"golang.org/x/crypto/ssh"
	"strings"
	"sync"
	"time"
)

type Addr struct {
	host string
	user string
	pass string
}

func SSH_Scan(hosts []string, timeout int64, workers int) {
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
				SshConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["ssh"]
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

func SshConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         time.Duration(timeout) * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", host, config)
	if err == nil {
		defer client.Close()
		session, errs := client.NewSession()
		if errs == nil {
			defer session.Close()
			wg.Add(1)
			msg := fmt.Sprintf("[SSH] %v %v:%v", host, user, password)
			res <- msg
		} else {
			msg := fmt.Sprintf("[SSH-Cracking] %v %v:%v", host, user, password)
			fmt.Println(msg)
			return
		}
	} else {
		msg := fmt.Sprintf("[SSH-Cracking] %v %v:%v", host, user, password)
		fmt.Println(msg)
		return
	}
}
