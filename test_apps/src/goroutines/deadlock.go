package main

import (
	"fmt"
	"sync"
	"time"
)

func main() {
	a := 0
	var m1 sync.Mutex
	var m2 sync.Mutex
	go func() {
		m1.Lock()
		m2.Lock()
		a++
		fmt.Println(a)
		m2.Unlock()
		m1.Unlock()
	}()
	go func() {
		m2.Lock()
		m1.Lock()
		a++
		fmt.Println(a)
		m1.Unlock()
		m2.Unlock()
	}()
	time.Sleep(time.Second)
}
