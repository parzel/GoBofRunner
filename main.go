package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/parzel/GoBofRunner/bof"
)

func main() {
	rawCoff, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	bofArgs := bof.BOFArgsBuffer{
		Buffer: new(bytes.Buffer),
	}

	for _, arg := range os.Args[1:] {
		a := strings.SplitN(arg, ":", 2)
		switch a[0] {
		case "integer":
			fallthrough
		case "int":
			x, _ := strconv.Atoi(a[1])
			err = bofArgs.AddInt(uint32(x))
		case "string":
			err = bofArgs.AddString(a[1])
		case "wstring":
			err = bofArgs.AddWString(a[1])
		case "short":
			x, _ := strconv.Atoi(a[1])
			err = bofArgs.AddShort(uint16(x))
		}
		if err != nil {
			return
		}
	}

	BeaconData, _ := bofArgs.GetBuffer()
	fmt.Printf("Beacondata: %x\n", BeaconData)
	output := bof.ParseCoff(rawCoff, BeaconData)
	fmt.Println(output)
}
