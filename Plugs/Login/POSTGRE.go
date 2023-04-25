package Login

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/wintrysec/Taiji/Common"
	"strings"
	"sync"
	"time"
)

func Postgres_Scan(hosts []string, timeout int64, workers int) {
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
				PostgresConnect(addr.host, addr.user, addr.pass, timeout, results, &wg)
				wg.Done() //添加一个HOST扫描
			}
		}()

	}

	//添加扫描目标
	var Dict []string
	if Common.User != "" && Common.Pwd != "" {
		Dict = Common.SetPassDict()
	} else {
		Dict = Common.Passdict["postgresql"]
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

// PostgresConnect 建立连接
func PostgresConnect(host string, user string, password string, timeout int64, res chan<- string, wg *sync.WaitGroup) {
	ip := strings.Split(host, ":")[0]
	port := strings.Split(host, ":")[1]
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", user, password, ip, port, "postgres", "disable")
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(timeout) * time.Second)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			wg.Add(1)
			msg := fmt.Sprintf("[Postgresql] %v %v:%v", host, user, password)
			res <- msg
		} else {
			msg := fmt.Sprintf("[Postgresql-Crack] %v %v:%v", host, user, password)
			fmt.Println(msg)
			return
		}
	} else {
		return
	}
}
