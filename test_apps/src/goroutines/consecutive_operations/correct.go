package main

import (
	"fmt"
	"sync"
)
var l sync.Mutex
var a string

func f() {
	a = "hello, world"
	l.Unlock()
}

func main() {
	l.Lock()
	go f()
	l.Lock()
	fmt.Println(a)
}