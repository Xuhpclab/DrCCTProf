package main

import (
	"sync"
	"time"
)

type ms struct {
	m1 sync.Mutex
	m2 sync.Mutex
}

func main() {
	var m ms
	go func() {
		m.m1.Lock()
		m.m2.Lock()
		m.m2.Unlock()
		m.m1.Unlock()

		m.m1.Lock()
		m.m2.Lock()
		m.m2.Unlock()
		m.m1.Unlock()
	}()
	go func() {
		m.m2.Lock()
		m.m1.Lock()
		m.m1.Unlock()
		m.m2.Unlock()
	}()
	time.Sleep(2*time.Second)
}