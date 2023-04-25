package Common

import (
	"bufio"
	"io"
	"os"
	"strings"
)

func Gettarget(filepath string) (Targets string) {
	file, err := os.OpenFile(filepath, os.O_RDONLY, 0666)
	if err != nil {
		return ""
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	var TmpTargets []string
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		TmpTargets = append(TmpTargets, string(line))

	}
	Targets = strings.Join(TmpTargets, ",")
	return Targets
}
