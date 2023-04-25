package Login

import (
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/wintrysec/Taiji/Common"
	"strings"
	"sync"
	"time"
)

func Mssql_Scan(hosts []string, timeout int64, workers int) {
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
				MssqlConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["mssql"]
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

func MssqlConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	ip := strings.Split(host, ":")[0]
	port := strings.Split(host, ":")[1]
	dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", ip, user, password, port, time.Duration(timeout)*time.Second)
	db, err := sql.Open("mssql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(timeout) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			wg.Add(1)
			msg := fmt.Sprintf("[MSSQL] %v %v:%v", host, user, password)
			res <- msg
		} else {
			msg := fmt.Sprintf("[MSSQL-Crack] %v %v:%v", host, user, password)
			fmt.Println(msg)
			return
		}
	}
}
