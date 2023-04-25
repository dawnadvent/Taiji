package Common

import "flag"

func Flag(Info *HostInfo) {
	flag.StringVar(&Info.Host, "ip", "127.0.0.1", "Scan target: 192.168.1.1-255 | 192.168.1.1/24 | xxx.com")
	flag.StringVar(&Info.Ports, "port", DefaultPorts, "Scan Ports: 1-65535 | 22,80,443")
	flag.Int64Var(&Info.Timeout, "time", 5, "Connect Timeout")
	flag.IntVar(&Info.Threads, "c", 900, "Threads")
	flag.StringVar(&ScanType, "m", "all", "Scan Type: all|icmp|icon_hash|webscan")
	flag.BoolVar(&NoPing, "np", false, "No ping")
	flag.BoolVar(&Log, "log", false, "Save scan logs")
	flag.StringVar(&Logpath, "out", "./logs.txt", "The logs to save path")
	flag.BoolVar(&Vuln, "vuln", false, "password and system vuln scan")
	flag.StringVar(&User, "user", "", "Username or path to a file with usernames")
	flag.StringVar(&Pwd, "pwd", "", "Password or path to a file with passwords")
	flag.Parse()
}
