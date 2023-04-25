package Plugs

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/twmb/murmur3"
	"github.com/wintrysec/Taiji/Common"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"hash"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// 字符编码
var (
	Charsets = []string{"utf-8", "gbk", "gb2312"}
)

type AddrHost struct {
	host string
}

// 识别Web应用的指纹信息
type CheckDatas struct {
	Body    []byte
	Headers string
}

func WebScan(hosts []string, timeout int64, workers int) {
	var wg sync.WaitGroup
	Addrs := make(chan AddrHost, len(hosts))
	results := make(chan string, len(hosts))

	//前缀输出
	Common.Savelog(fmt.Sprintf("================================================================================================================"))
	Common.Savelog(fmt.Sprintf("[Web] %-30s %4v %-6v %-25s %v\t\t %s", "          URL", " Code", "Length", "  Server", " CMS", "   Title"))
	Common.Savelog(fmt.Sprintf("================================================================================================================"))

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
				Webtitle(addr.host, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, host := range hosts {
		wg.Add(1)
		Addrs <- AddrHost{host}
	}
	wg.Wait()
	close(Addrs)
	close(results)
}

// 获取网站标题信息
func Webtitle(host string, res chan<- string, timeout int64, wg *sync.WaitGroup) {
	//分辨HTTP协议版本
	protocol := GetProtocol(host, timeout)
	url := protocol + "://" + host

	//仅计算图标HASH
	if Common.ScanType == "icon_hash" {
		_, icohash, _, _ := Caclmmh3(url, "calc")
		fmt.Println("此应用的图标哈希值(FOFA):", icohash)
		return
	}

	//设置请求参数
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")
	req.Header.Set("Cookie", "rememberMe=1")

	//设置http客户端参数
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //忽略https验证
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second, //设置超时连接
		//CheckRedirect: func(req *http.Request, via []*http.Request) error {
		//	return http.ErrUseLastResponse /* 不进入重定向 */
		//},
	}

	//发送HTTP请求
	resp, err := client.Do(req)
	if err == nil {
		go func() {
			if resp != nil {
				defer resp.Body.Close()
			}
		}()

		//获取响应值
		var title string
		var text []byte
		Server := resp.Header.Get("Server")
		body, _ := getRespBody(resp)
		CLength := len(body)
		re := regexp.MustCompile("(?ims)<title>(.*)</title>")
		find := re.FindSubmatch(body)

		// 判断Content-Type 字符集编码
		GetEncoding := func() string {
			r1, err := regexp.Compile(`(?im)charset=\s*?([\w-]+)`)
			if err != nil {
				return ""
			}
			headerCharset := r1.FindString(resp.Header.Get("Content-Type"))
			if headerCharset != "" {
				for _, v := range Charsets { // headers 编码优先，所以放在前面
					if strings.Contains(strings.ToLower(headerCharset), v) == true {
						return v
					}
				}
			}

			r2, err := regexp.Compile(`(?im)<meta.*?charset=['"]?([\w-]+)["']?.*?>`)
			if err != nil {
				return ""
			}
			htmlCharset := r2.FindString(string(body))
			if htmlCharset != "" {
				for _, v := range Charsets {
					if strings.Contains(strings.ToLower(htmlCharset), v) == true {
						return v
					}
				}
			}
			return ""
		}
		encode := GetEncoding()

		//获取网站标题
		if len(find) > 1 {
			text = find[1]
			if strings.Contains(strings.ToLower(encode), "gb") {
				titleGBK, errgb := Decodegbk(text)
				if errgb == nil {
					title = string(titleGBK)
				}
			} else {
				title = string(text)
			}
		} else {
			title = "None"
		}
		title = strings.Trim(title, "\r\n \t")
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		title = strings.Replace(title, "&#8211;", "-", -1)
		title = strings.Split(title, "</")[0]

		//获取Web指纹信息
		var CheckData []CheckDatas
		CheckData = append(CheckData, CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
		app_name, value, class := WebCms(url, CheckData)
		if class == "" {
		} //空代码 无用
		if resp.StatusCode == 404 && ("weblogic" == value) {
			msg := fmt.Sprintf("[Web] %-30s |%3v| %-8v %-25s %-21v %s", url, resp.StatusCode, CLength, "Weblogic", app_name[0], title)
			res <- msg
			wg.Add(1)
		} else if resp.StatusCode == 404 {

		} else {
			msg := fmt.Sprintf("[Web] %-30s |%3v| %-8v %-25s %-21v %s", url, resp.StatusCode, CLength, Server, app_name[0], title)
			res <- msg
			wg.Add(1)
		}

	}
}

// 获取响应体
func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

// 获取Web协议
func GetProtocol(host string, Timeout int64) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(Timeout) * time.Second}, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	protocol := "http"
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}

// 识别Web应用的指纹信息
func WebCms(url string, CheckData []CheckDatas) (infoname []string, value string, class string) {
	var matched bool

	for _, data := range CheckData {
		for _, rule := range RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
				value = rule.value
				class = rule.class
			}
		}
	}

	//图标HASH识别
	flag, name, value_tmp, class_tmp := Caclmmh3(url, "cc") //通过图标url计算hash
	if flag == true {
		infoname = append(infoname, name)
		value = value_tmp
		class = class_tmp
	}

	infoname = removeDuplicateElement(infoname)

	if len(infoname) > 0 {
		return infoname, value, class
	}
	return []string{""}, "", "其他设备"
}

func Caclmmh3(url string, calc string) (flag bool, name string, value string, class string) {
	url = url + "/favicon.ico"
	Body := HttpGet(url)
	mmh3hash := Mmh3Hash32(StandBase64(Body))
	if calc == "calc" {
		return false, mmh3hash, "", "其他设备"
	}
	for _, mmh3data := range Mh3Datas {
		if mmh3hash == mmh3data.mmh3 {
			value = mmh3data.value
			class = mmh3data.class
			return true, mmh3data.Name, value, class
		}
	}
	return false, "未知资产", "", "其他设备"
}

// 计算 mmh3 hash
func Mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	h32.Write(raw)
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

// 计算 base64 的值
func StandBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

// 去重
func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// 发起HTTP请求
func HttpGet(url string) []byte {
	//设置http客户端参数
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //忽略https验证
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(5) * time.Second,
		//CheckRedirect: func(req *http.Request, via []*http.Request) error {
		//	return http.ErrUseLastResponse /* 不进入重定向 */
		//},
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-agent", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := getRespBody(resp)
		return body
	}
	return nil
}

// GBK解码
func Decodegbk(s []byte) ([]byte, error) {
	I := bytes.NewReader(s)
	O := transform.NewReader(I, simplifiedchinese.GBK.NewDecoder())
	d, e := io.ReadAll(O)
	if e != nil {
		return nil, e
	}
	return d, nil
}
