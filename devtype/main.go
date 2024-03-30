package main

import (
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
)

func main() {
	link, err := netlink.LinkByName(os.Args[1])
	if err != nil {
		fmt.Println(err)
	}
	println(link.Type())

}
