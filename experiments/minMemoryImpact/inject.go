package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/fkie-cad/yapscan/procio"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("ERROR: Invalid argument!")
		fmt.Println("Usage: inject <pid>")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("ERROR: Invalid argument, %v!\n", err)
		fmt.Println("Usage: inject <pid>")
		os.Exit(1)
	}

	fmt.Println("Opening process...")
	proc, err := procio.OpenProcess(pid)
	if err != nil {
		panic(err)
	}

	fmt.Println("Attaching...")
	injector, err := procio.NewInjector(proc)
	if err != nil {
		panic(err)
	}

	segments, err := proc.MemorySegments()
	if err != nil {
		panic(err)
	}
	advSeg := segments[len(segments)-2]

	ass := procio.NewAssembler()
	code := ass.Madvise(advSeg.BaseAddress, advSeg.Size, syscall.MADV_DONTNEED).
		Int3().
		Assemble()

	fmt.Printf("Madvising 0x%X", advSeg.BaseAddress)

	for _, c := range code {
		fmt.Printf("%02X ", c)
	}
	fmt.Println()

	var line string
	fmt.Scanln(&line)

	fmt.Println("Injecting...")
	shell, err := injector.Inject(code)
	if err != nil {
		panic(err)
	}

	fmt.Println("Waiting for breakpoint...")
	err = shell.WaitForBreakpoint()
	if err != nil {
		panic(err)
	}

	fmt.Scanln(&line)

	fmt.Println("Cleaning up injection...")
	err = shell.Close()
	if err != nil {
		panic(err)
	}

	fmt.Println("Detaching...")
	err = injector.Close()
	if err != nil {
		panic(err)
	}
}
