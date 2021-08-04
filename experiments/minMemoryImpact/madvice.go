// +build linux
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

// #include <sys/mman.h>
import "C"

const length = 4096 * 1024 * 1024

func printIncoreInfo(addr uintptr) {
	incoreVec := make([]byte, (length+4095)/4096)
	_, _, errno := syscall.Syscall(syscall.SYS_MINCORE, addr, length, uintptr(unsafe.Pointer(&incoreVec[0])))
	if errno != 0 {
		panic(errno.Error())
	}

	nLoaded := 0
	for _, state := range incoreVec {
		nLoaded += int(state)
	}

	fmt.Printf("Loaded: %d/%d\n", nLoaded, len(incoreVec))
}

func waitInput() {
	var input string
	fmt.Scanln(&input)
}

func main() {
	pid := os.Getpid()
	fmt.Println(pid)

	sigChan := make(chan os.Signal, 2)
	go func() {
		for sig := range sigChan {
			fmt.Printf("SIGNAL: %v", sig)
		}
	}()
	signal.Notify(sigChan)

	memory, err := syscall.Mmap(-1, 0, length, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
	if err != nil {
		panic(err)
	}
	addr := uintptr(unsafe.Pointer(&memory[0]))

	fmt.Printf("Allocated: 0x%X\n", addr)

	printIncoreInfo(addr)
	waitInput()

	for i := 0; i < length; i += 4096 {
		memory[i] = 42
	}
	fmt.Printf("Memory touched.\n")

	printIncoreInfo(addr)
	waitInput()

	syscall.Madvise(memory, syscall.MADV_DONTNEED)
	memory[0] = 42
	fmt.Printf("Madvice given.\n")

	printIncoreInfo(addr)
	waitInput()

	for i := 0; i < length; i += 4096 {
		memory[i] = 42
	}
	fmt.Printf("Memory touched.\n")

	printIncoreInfo(addr)
	waitInput()
}
