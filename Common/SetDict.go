package Common

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

func GetUsers(filepath string) []string {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var Usernames []string
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		Usernames = append(Usernames, string(line))
	}
	return Usernames
}

func GetPwds(filepath string) []string {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0666)
	if err != nil {
		return nil
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var Passwors []string
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		Passwors = append(Passwors, string(line))
	}
	return Passwors
}

func SetPassDict() []string {
	PassDicts := []string{}
	if strings.Contains(User, ".txt") && strings.Contains(Pwd, ".txt") {
		for _, user := range GetUsers(User) {
			for _, pass := range GetPwds(Pwd) {
				dict := fmt.Sprintf("%s:%s", user, pass)
				PassDicts = append(PassDicts, dict)
			}
		}
	} else if User == "" && strings.Contains(Pwd, ".txt") {
		for _, pass := range GetPwds(Pwd) {
			dict := fmt.Sprintf(":%s", pass)
			PassDicts = append(PassDicts, dict)
		}
	} else {
		PassDicts = append(PassDicts, fmt.Sprintf("%s:%s", User, Pwd))
	}
	return PassDicts
}

// 默认字典
var Passdict = map[string][]string{
	"ftp": {
		"anonymous:anonymous",
		"ftp:ftp",
		"admin:admin",
	},

	"mysql": {
		"root:root",
		"root:123456",
		"root:123123",
		"root:root123",
		"root:root@123",
		"root:admin@123",
		"root:admin123",
	},

	"mssql": {
		"sa:sa",
		"sa:sa123",
		"sa:sa@123",
		"sa:123456",
		"sa:123123",
		"sa:admin",
		"sa:admin@123",
	},

	"smb": {
		"administrator:!QAZ@WSX#EDC",
		"guest:",
	},

	"postgresql": {
		"postgres:123456",
		"postgres:passwd",
		"postgres:password",
		"postgres:admin@123",
	},

	"ssh": {
		"root:root",
		"root:root123",
		"root:root@123",
		"root:123456",
		"root:123123",
		"root:112233",
		"root:654321",
		"root:111111",
		"root:000000",
		"root:admin@123",
		"root:admin123",
		"root:pass123",
		"admin:admin",
		"admin:123456",
		"admin:admin@123",
	},

	"redis": {
		":123456",
		":redis",
		":passwd",
		":password",
	},

	"mongodb": {
		"admin:admin",
		"admin:123456",
	},
}
