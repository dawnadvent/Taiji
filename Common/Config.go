package Common

var DefaultPorts = "21,22,80,81,82,85,135,443,445,554,902,912,993,995,1080,1099,1433,1443,1883,2443,3000,3002,3306,3389,4430,4730,5000,5060,5222,5432,5555,5601,5672,5900,5938,5984,6000,6050,6060,6379,7001,7002,7007,7010,7077,7100,7547,7777,7801,8000,8001,8002,8003,8004,8005,8006,8008,8009,8010,8011,8014,8060,8070,8080,8081,8082,8083,8085,8086,8087,8088,8089,8090,8091,8093,8098,8099,8128,8180,8181,8197,8443,8545,8554,8686,8880,8881,8883,8888,8899,8970,8989,9000,9001,9002,9003,9010,9042,9043,9090,9091,9092,9100,9191,9200,9303,9305,9306,9307,9418,9443,9527,9876,9898,9900,9998,9999,10001,10002,10443,11211,18001,18080,18081,27017,50000,50070,60001,60002,61616,65535"

// 主机信息
type HostInfo struct {
	Host    string
	Ports   string
	Threads int
	Timeout int64
}

// 扫描器参数
var (
	Log      bool
	Logpath  string
	NoPing   bool
	ScanType string
	Vuln     bool
	User     string
	Pwd      string
)
