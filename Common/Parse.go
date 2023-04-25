package Common

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// 解析URL
func ParseURL(urls string) (hosts []string) {
	//按照逗号把传入的端口分割切片
	slices := strings.Split(urls, ",")
	for _, url := range slices {
		url = strings.ReplaceAll(url, "http://", "")
		url = strings.ReplaceAll(url, "https://", "")
		url = strings.ReplaceAll(url, " ", "")
		hosts = append(hosts, url)
	}
	return hosts
}

// 解析端口
func ParsePort(ports string) (Ports []int) {
	if ports == "" {
		return
	}
	//按照逗号把传入的端口分割切片
	slices := strings.Split(ports, ",")

	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port

		//端口范围处理
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])

			//防止用户反向写端口范围
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}

		}
		//转换为数字类型（不是端口范围的在这里也会加入列表）
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)

		for i := start; i <= end; i++ {
			Ports = append(Ports, i)
		}
	}
	return Ports
}

// 解析IP格式-入口
func ParseIP(ip string) (hosts []string) {
	if strings.Contains(ip, ",") {
		IPList := strings.Split(ip, ",")
		var ips []string
		for _, ip = range IPList {
			ips = ParseIPone(ip)
			hosts = append(hosts, ips...)
		}
	} else {
		hosts = ParseIPone(ip)
	}
	return hosts
}

// 单个IP解析逗号分隔
func ParseIPone(ip string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(ip[len(ip)-3:], "/24"):
		return ParseIPC(ip)
	case strings.Contains(ip[len(ip)-3:], "/16"):
		return ParseIPB(ip)
	case strings.Contains(ip[len(ip)-2:], "/8"):
		return ParseIPA(ip)
	case strings.Count(ip, "-") == 1:
		return ParseIPD(ip)
	case reg.MatchString(ip):
		_, err := net.LookupHost(ip)
		if err != nil {
			return nil
		}
		return []string{ip}
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

// 解析 CIDR IP /24
func ParseIPC(ip string) []string {
	realIP := ip[:len(ip)-3]
	testIP := net.ParseIP(realIP)
	if testIP == nil {
		return nil
	}

	IPrange := strings.Join(strings.Split(realIP, ".")[0:3], ".")
	var AllIP []string
	for i := 0; i <= 255; i++ {
		AllIP = append(AllIP, IPrange+"."+strconv.Itoa(i))
	}
	return AllIP
}

// B段IP /16
func ParseIPB(ip string) []string {
	realIP := ip[:len(ip)-3]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return nil
	}
	IPrange := strings.Join(strings.Split(realIP, ".")[0:2], ".")
	var AllIP []string
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			AllIP = append(AllIP, IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b))
		}
	}
	return AllIP
}

// A段IP /8
func ParseIPA(ip string) []string {
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return nil
	}
	IPrange := strings.Join(strings.Split(realIP, ".")[0:1], ".")
	var AllIP []string
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			AllIP = append(AllIP, IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b)+"."+strconv.Itoa(1))
			AllIP = append(AllIP, IPrange+"."+strconv.Itoa(a)+"."+strconv.Itoa(b)+"."+strconv.Itoa(254))
		}
	}
	return AllIP
}

// 解析范围IP,for example: 192.168.111.1-255,192.168.111.1-192.168.112.255
func ParseIPD(ip string) []string {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []string
	if len(IPRange[1]) < 4 {
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		SplitIP := strings.Split(IPRange[0], ".")
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, ip)
		}
	}

	return AllIP

}
