package main

import (
	"fmt"
	"sync"
	"time"
)

type ms struct {
	m1 sync.Mutex
	m2 sync.Mutex
	m3 sync.Mutex
	m4 sync.Mutex
	m5 sync.Mutex
	m6 sync.Mutex
}

func main() {
	a := 0
	var m ms
	go func() {
		m.m1.Lock()
		m.m2.Lock()
		a++
		fmt.Println(a)
		m.m2.Unlock()
		m.m1.Unlock()
	}()
	go func() {
		m.m2.Lock()
		m.m3.Lock()
		a++
		fmt.Println(a)
		m.m3.Unlock()
		m.m2.Unlock()
	}()
	go func() {
		m.m3.Lock()
		m.m4.Lock()
		m.m5.Lock()
		a++
		fmt.Println(a)
		m.m5.Unlock()
		m.m4.Unlock()
		m.m3.Unlock()
	}()
	go func() {
		m.m5.Lock()
		m.m1.Lock()
		a++
		fmt.Println(a)
		m.m1.Unlock()
		m.m5.Unlock()
	}()
	go func() {
		m.m4.Lock()
		m.m6.Lock()
		a++
		fmt.Println(a)
		m.m6.Unlock()
		m.m4.Unlock()
	}()
	time.Sleep(time.Second)
}
