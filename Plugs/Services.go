package Plugs

import (
	"fmt"
	"github.com/wintrysec/Taiji/Common"
	"strings"
)

// 已知端口服务表(非Web服务)
var (
	SerPorts = []string{
		"21",    //FTP
		"22",    //SSH
		"23",    //Telnet
		"25",    //SMTP
		"53",    //DNS
		"110",   //POP3
		"135",   //RPC
		"139",   //NETBIOS
		"143",   //IMAP
		"445",   //SMB
		"554",   //RTSP
		"558",   //RTSP
		"8554",  //RTSP
		"902",   //VMware
		"912",   //VMware
		"1080",  //Proxy
		"1433",  //MSSQL
		"1521",  //Oracle
		"2049",  //NFS
		"3306",  //MySQL
		"3389",  //RDP
		"5432",  //PostgreSQL
		"5900",  //VNC
		"6379",  //Redis
		"11211", //MemCache
		"27017", //MongoDB
	}

	//有下一步操作的服务列表变量,比如口令爆破,Web指纹识别
	WebHosts []string //疑似Web服务的主机列表
	FTP      []string
	SSH      []string
	SMB      []string
	MSSQL    []string
	MySQL    []string
	REDIS    []string
	POSTSQL  []string
	MEMCACHE []string
	MONGODB  []string
)

// 端口服务识别
func GetService(hosts []string) {
	for _, host := range hosts {
		//ip := strings.Split(host, ":")[0]
		port := strings.Split(host, ":")[1]
		if in(port, SerPorts) {
			//服务爆破进列表
			switch port {
			case "21":
				FTP = append(FTP, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "FTP")
				Common.Savelog(msg)
			case "22":
				SSH = append(SSH, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "SSH")
				Common.Savelog(msg)
			case "135":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "RPC")
				Common.Savelog(msg)
			case "445":
				SMB = append(SMB, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "SMB")
				Common.Savelog(msg)
			case "3389":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "RDP")
				Common.Savelog(msg)
			case "3306":
				MySQL = append(MySQL, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "MySQL")
				Common.Savelog(msg)
			case "1433":
				MSSQL = append(MSSQL, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "MSSQL")
				Common.Savelog(msg)
			case "6379":
				REDIS = append(REDIS, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "Redis")
				Common.Savelog(msg)
			case "27017":
				MONGODB = append(MONGODB, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "MongoDB")
				Common.Savelog(msg)
			case "5432":
				POSTSQL = append(POSTSQL, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "Postgresql")
				Common.Savelog(msg)
			case "11211":
				MEMCACHE = append(MEMCACHE, host)
				msg := fmt.Sprintf("[Protocol] %v %v", host, "Memcached")
				Common.Savelog(msg)
			case "558":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "RTSP")
				Common.Savelog(msg)
			case "554":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "RTSP")
				Common.Savelog(msg)
			case "8554":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "RTSP")
				Common.Savelog(msg)
			case "1521":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "Orcale")
				Common.Savelog(msg)
			case "53":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "DNS")
				Common.Savelog(msg)
			case "25":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "SMTP")
				Common.Savelog(msg)
			case "110":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "POP3")
				Common.Savelog(msg)
			case "143":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "IMAP")
				Common.Savelog(msg)
			case "902":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "VMware")
				Common.Savelog(msg)
			case "912":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "VMware")
				Common.Savelog(msg)
			case "5900":
				msg := fmt.Sprintf("[Protocol] %v %v", host, "VNC")
				Common.Savelog(msg)
			default:
				msg := fmt.Sprintf("[Protocol] %v %v", host, "Unkown Protocol")
				Common.Savelog(msg)
			}
		} else {
			//加入Web扫描队列
			WebHosts = append(WebHosts, host)
		}
	}
}
