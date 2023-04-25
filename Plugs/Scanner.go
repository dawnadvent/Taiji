package Plugs

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"github.com/wintrysec/Taiji/Plugs/Login"
	"strings"
	"time"
)

var AliveHosts []string //存活服务列表
// 扫描任务调度
func Scan(Info Common.HostInfo) {
	//从文件读取目标
	if strings.Contains(Info.Host, ".txt") {
		Info.Host = Common.Gettarget(Info.Host)
	}
	//URL探活
	if Common.ScanType == "webscan" {
		urls := Common.ParseURL(Info.Host)
		//Web扫描,指纹识别
		WebScan(urls, Info.Timeout, Info.Threads)
		return
	}
	//解析IP地址
	ips := Common.ParseIP(Info.Host)
	if Common.NoPing {
		//禁ping扫描
		start_port := time.Now()
		AliveHosts = PortScan(ips, Info.Ports, Info.Timeout, Info.Threads)
		end_port := time.Since(start_port)
		msg := fmt.Sprintf("Find %v Alive Port,Spend Time %v\n", len(AliveHosts), end_port)
		Common.Savelog(msg)
	} else {
		//Ping主机存活探测
		start := time.Now()
		AliveAddress := IcmpScan(ips, Info.Threads)
		end := time.Since(start)
		msg := fmt.Sprintf("Scan %v Hosts,Find %v Alive,Spend_Time%v", len(ips), len(AliveAddress), end)
		Common.Savelog(msg)
		AliveC := GetAliveC(AliveAddress)
		for _, AC := range AliveC {
			Common.Savelog(AC)
		}
		Common.Savelog(fmt.Sprintf("Alive C Sections,%v", len(AliveC)))
		if Common.ScanType == "icmp" {
			return //仅ICMP扫描，结束后退出
		}
		//端口扫描开始
		var Port_IPS []string
		for _, ip := range AliveAddress {
			Port_IPS = append(Port_IPS, ip)
		}
		start = time.Now()
		AliveHosts = PortScan(Port_IPS, Info.Ports, Info.Timeout, Info.Threads)
		end = time.Since(start)
		msg = fmt.Sprintf("Find %v Alive Port,Spend Time %v\n", len(AliveHosts), end)
		Common.Savelog(msg)
	}

	//识别端口服务
	GetService(AliveHosts)

	//Web扫描,指纹识别
	WebScan(WebHosts, Info.Timeout, Info.Threads)

	//系统漏洞扫描
	if Common.Vuln {
		Ms17010_Scan(SMB, Info.Timeout, Info.Threads)
		SMBGhost_Scan(SMB, Info.Timeout, Info.Threads)
		Login.SSH_Scan(SSH, Info.Timeout, Info.Threads)
		Login.Redis_Scan(REDIS, Info.Timeout, Info.Threads)
		Login.Memcached_Scan(MEMCACHE, Info.Timeout, Info.Threads)
		Login.Mongo_Scan(MONGODB, Info.Timeout, Info.Threads)
		Login.Postgres_Scan(POSTSQL, Info.Timeout, Info.Threads)
		Login.Mysql_Scan(MySQL, Info.Timeout, Info.Threads)
		Login.Mssql_Scan(MSSQL, Info.Timeout, Info.Threads)
		Login.Smb_Scan(SMB, Info.Timeout, Info.Threads)
		Login.Ftp_Scan(FTP, Info.Timeout, Info.Threads)
	}
}
