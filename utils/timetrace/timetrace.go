package timetrace

import (
	"fmt"
	"time"
)

// TrackFunc prints the execution time of the enclosing function.
// Usage: defer timetrace.TrackFunc("yourFuncName")()
func TrackFunc(name string) func() {
	start := time.Now()
	return func() {
		elapsed := time.Since(start)
		fmt.Printf("⏱ %s took %s\n", name, elapsed)
	}
}
