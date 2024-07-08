package main

import (
	"fmt"

	"github.com/nghtf/cli7z"
)

func main() {

	file, err := cli7z.Open("./file.zip")
	if err != nil {
		fmt.Println(err)
		fmt.Println(file.ErrorState)
		return
	}
	fmt.Println(file.Listing)
}
