package main

import (
	"sync"
	"time"
	"fmt"
)

var l sync.Mutex
var a string

func f() {
	l.Lock()
	l.Lock()
	a = "hello, world"
}

func main() {
	go f()
	time.Sleep(time.Second)
	fmt.Println(a)
}