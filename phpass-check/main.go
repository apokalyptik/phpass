package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/apokalyptik/phpass"
)

var pw = ""
var hash = ""

func main() {
	flag.StringVar(&hash, "hash", "", "Hash to validate against")
	flag.StringVar(&pw, "pw", "", "Password validate")
	flag.Parse()
	if len(flag.Args()) > 1 {
		if pw == "" {
			pw = strings.Join(flag.Args()[1:], " ")
		}
		if hash == "" {
			hash = flag.Args()[0]
		}
	}
	var h = phpass.New(nil)
	if h.Check([]byte(pw), []byte(hash)) {
		fmt.Println("true")
	} else {
		fmt.Println("false")
		os.Exit(1)
	}
}
