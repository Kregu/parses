package main

import (
	"encoding/xml"
	"fmt"
	"os"
)

func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) < 2 {
		fmt.Println("\"Enter pst Command file\"")
	}
	//a := argsWithoutProg[0]
	commands := argsWithoutProg[0 : len(argsWithoutProg)-1]
	pathFile := argsWithoutProg[len(argsWithoutProg)-1]
	file, _ := os.ReadFile(pathFile)

	var s Selftest
	xml.Unmarshal(file, &s)

	for _, command := range commands {

		if command == "-s" {

			fmt.Println(s.Servicetag[0])
		} else if command == "-m" {

			fmt.Println(s.Model)
		} else if command == "-i" {
			for _, inter := range s.Interface {

				fmt.Println(inter.Name)
			}
		}

	}
}
