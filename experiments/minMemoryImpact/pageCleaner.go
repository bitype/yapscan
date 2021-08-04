package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fkie-cad/yapscan/procio"
)

func waitInput() {
	var input string
	fmt.Scanln(&input)
}

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
	defer func() {
		err := proc.Close()
		if err != nil {
			panic(err)
		}
	}()

	fmt.Println("Creating cleaner...")
	cleaner, err := procio.NewPageCleaner(proc)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := cleaner.Close()
		if err != nil {
			panic(err)
		}
	}()

	segments, err := proc.MemorySegments()
	if err != nil {
		panic(err)
	}

	fmt.Println("Taking snapshots...")
	snapshots := make([]*procio.PageStateSnapshot, len(segments))
	for i, seg := range segments {
		snapshots[i], err = cleaner.Snapshot(seg)
		//fmt.Printf("%4d / %4d\r", i+1, len(snapshots))
		if err != nil {
			fmt.Printf("ERROR taking snapshot for 0x%X: %v\n", seg.BaseAddress, err)
		}
	}
	fmt.Println()
	fmt.Printf("%d snapshots taken.\n", len(snapshots))

	waitInput()

	nFailed := 0
	fmt.Println("Restoring...")
	for _, snapshot := range snapshots {
		err = snapshot.Restore()
		if err != nil {
			fmt.Printf("ERROR restoring snapshot: %v\n", err)
			nFailed++
		}
	}
	fmt.Printf("%d snapshots restored.\n", len(snapshots)-nFailed)
}
