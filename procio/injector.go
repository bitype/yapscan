package procio

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/targodan/go-errors"
)

// This should be sufficient for advising ~5MB of memory at a time
// if we are being stupid about it.
const minInjectionSiteSize = 50 * 1024

const pageSize = 4096

type Registers syscall.PtraceRegs

type Assembler struct {
	buffer *bytes.Buffer
}

func NewAssembler() *Assembler {
	return &Assembler{&bytes.Buffer{}}
}

func (a *Assembler) Madvise(addr uintptr, length uintptr, advice int) *Assembler {
	a.buffer.Write([]byte{0x48, 0xC7, 0xC2}) // mov rdx, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(advice))

	a.buffer.Write([]byte{0x48, 0xBE}) // mov rsi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(length))

	a.buffer.Write([]byte{0x48, 0xBF}) // mov rdi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(addr))

	a.buffer.Write([]byte{0x48, 0xC7, 0xC0}) // mov rax, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(syscall.SYS_MADVISE))

	a.buffer.Write([]byte{0x0F, 0x05}) // syscall

	return a
}

func (a *Assembler) Mincore(addr uintptr, length uintptr, outVector uintptr) *Assembler {
	// int mincore(void *addr, size_t length, unsigned char *vec);

	a.buffer.Write([]byte{0x48, 0xBA}) // mov rdx, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(outVector))

	a.buffer.Write([]byte{0x48, 0xBE}) // mov rsi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(length))

	a.buffer.Write([]byte{0x48, 0xBF}) // mov rdi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(addr))

	a.buffer.Write([]byte{0x48, 0xC7, 0xC0}) // mov rax, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(syscall.SYS_MINCORE))

	a.buffer.Write([]byte{0x0F, 0x05}) // syscall

	return a
}

func (a *Assembler) MmapAnonymous(length uintptr, prot, flags int) *Assembler {
	// void *mmap(void *addr, size_t length, int prot, int flags,
	//                  int fd, off_t offset);

	flags |= syscall.MAP_ANONYMOUS

	a.buffer.Write([]byte{0x4D, 0x31, 0xC9}) // xor r9, r9 (offset = 0)

	a.buffer.Write([]byte{0x49, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF}) // mov r8, -1 (fd = -1)

	a.buffer.Write([]byte{0x48, 0xC7, 0xC2}) // mov rcx, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(flags))

	a.buffer.Write([]byte{0x48, 0xC7, 0xC2}) // mov rdx, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(prot))

	a.buffer.Write([]byte{0x48, 0xBE}) // mov rsi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(length))

	a.buffer.Write([]byte{0x48, 0x31, 0xff}) // xor rdi, rdi

	a.buffer.Write([]byte{0x48, 0xC7, 0xC0}) // mov rax, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(syscall.SYS_MMAP))

	a.buffer.Write([]byte{0x0F, 0x05}) // syscall

	return a
}

func (a *Assembler) Munmap(addr, length uintptr) *Assembler {
	// int munmap(void *addr, size_t length);

	a.buffer.Write([]byte{0x48, 0xBE}) // mov rsi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(length))

	a.buffer.Write([]byte{0x48, 0xBF}) // mov rdi, ...
	binary.Write(a.buffer, binary.LittleEndian, uint64(addr))

	a.buffer.Write([]byte{0x48, 0xC7, 0xC0}) // mov rax, ...
	binary.Write(a.buffer, binary.LittleEndian, uint32(syscall.SYS_MUNMAP))

	a.buffer.Write([]byte{0x0F, 0x05}) // syscall

	return a
}

func (a *Assembler) Int3() *Assembler {
	a.buffer.Write([]byte{0xCC}) // int 3
	return a
}

func (a *Assembler) Assemble() []byte {
	return a.buffer.Bytes()
}

type Injector struct {
	pid              int
	injectionAddress uintptr
	injectionMaxSize int
}

func NewInjector(process Process) (*Injector, error) {
	err := syscall.PtraceAttach(process.PID())
	if err != nil {
		return nil, err
	}

	inj := &Injector{pid: process.PID()}
	err = inj.searchInjectionSite(process)
	if err != nil {
		return nil, err
	}

	return inj, nil
}

type RegistersOrError struct {
	value interface{}
}

func (r *RegistersOrError) IsErr() bool {
	_, isErr := r.value.(error)
	return isErr
}

func (r *RegistersOrError) Err() error {
	return r.value.(error)
}

func (r *RegistersOrError) Registers() *Registers {
	regs, ok := r.value.(*Registers)
	if !ok {
		return nil
	}
	return regs
}

func (inj *Injector) RunRemoteCode(code []byte, expectedBreakpoints int) <-chan *RegistersOrError {
	outChan := make(chan *RegistersOrError)

	go func(outChan chan<- *RegistersOrError) {
		defer close(outChan)

		injection, err := inj.Inject(code)
		if err != nil {
			outChan <- &RegistersOrError{value: err}
			return
		}

		for i := 0; i < expectedBreakpoints; i++ {
			err = injection.WaitForBreakpoint()
			if err != nil {
				outChan <- &RegistersOrError{value: err}
				break
			}

			regs, err := inj.GetRegisters()
			if err != nil {
				outChan <- &RegistersOrError{value: err}
				break
			}
			outChan <- &RegistersOrError{value: regs}

			if i+1 < expectedBreakpoints {
				err = injection.Continue()
				if err != nil {
					outChan <- &RegistersOrError{value: err}
					break
				}
			}
		}

		err = injection.Close()
		if err != nil {
			outChan <- &RegistersOrError{value: err}
		}
	}(outChan)

	return outChan
}

func (inj *Injector) WaitForRemoteCodeFinish(c <-chan *RegistersOrError) error {
	var multiErr error
	for result := range c {
		if result.IsErr() {
			multiErr = errors.NewMultiError(multiErr, result.Err())
		}
	}
	return multiErr
}

func (inj *Injector) ReadMemory(address uintptr, out []byte) error {
	_, err := syscall.PtracePeekData(inj.pid, address, out)
	return err
}

func (inj *Injector) Continue() error {
	return syscall.PtraceCont(inj.pid, 0)
}

func (inj *Injector) Close() error {
	return syscall.PtraceDetach(inj.pid)
}

func (inj *Injector) searchInjectionSite(process Process) error {
	// Make sure we get a fresh copy
	cache, ok := process.(CachingProcess)
	if ok {
		cache.InvalidateCache()
	}

	segments, err := process.MemorySegments()
	if err != nil {
		return fmt.Errorf("could not find injection site, reason: %w", err)
	}
	found := inj.searchInjectionSiteInSegments(segments)
	if !found {
		return fmt.Errorf("could not find suitable injection site")
	}
	return nil
}

func (inj *Injector) searchInjectionSiteInSegments(segments []*MemorySegmentInfo) bool {
	for _, seg := range segments {
		if seg.SubSegments != nil && len(seg.SubSegments) > 0 {
			found := inj.searchInjectionSiteInSegments(seg.SubSegments)
			if found {
				return true
			}
		} else {
			if seg.CurrentPermissions.Execute && seg.Size >= minInjectionSiteSize {
				//if seg.CurrentPermissions.Write && seg.CurrentPermissions.Execute && seg.Size >= minInjectionSiteSize {
				inj.injectionAddress = seg.BaseAddress
				inj.injectionMaxSize = int(seg.Size)
				return true
			}
		}
	}
	return false
}

func (inj *Injector) Inject(code []byte) (*Injection, error) {
	if len(code) > inj.injectionMaxSize {
		return nil, fmt.Errorf("injection code too large")
	}
	return newInjection(inj.pid, inj.injectionAddress, code)
}

type Injection struct {
	pid               int
	pgid              int
	injectionAddress  uintptr
	originalCode      []byte
	originalRegisters syscall.PtraceRegs
}

func newInjection(pid int, injectionAddress uintptr, newCode []byte) (*Injection, error) {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return nil, fmt.Errorf("could not determine process gid, reason: %w", err)
	}

	inj := &Injection{
		pid:              pid,
		pgid:             pgid,
		injectionAddress: injectionAddress,
		originalCode:     make([]byte, len(newCode)),
	}
	err = syscall.PtraceGetRegs(pid, &inj.originalRegisters)
	if err != nil {
		return nil, fmt.Errorf("could not read target registers, reason: %w", err)
	}

	// TODO: test if something bad happens when we happen to be in a mapped shared-library
	//		if nothing bad happens: fuck it, just inject at RIP. Otherwise see if we can find
	//		the main image or something.
	injectionAddress = uintptr(inj.originalRegisters.Rip)
	inj.injectionAddress = injectionAddress

	_, err = syscall.PtracePeekData(pid, injectionAddress, inj.originalCode)
	if err != nil {
		return nil, fmt.Errorf("could not backup original program code, reason: %w", err)
	}

	_, err = syscall.PtracePokeData(pid, injectionAddress, newCode)
	if err != nil {
		return nil, fmt.Errorf("could not write injected program code, reason: %w", err)
	}

	modifiedRegs := inj.originalRegisters
	modifiedRegs.Rip = uint64(injectionAddress)

	err = syscall.PtraceSetRegs(pid, &modifiedRegs)
	if err != nil {
		return nil, fmt.Errorf("could not write target registers, reason: %w", err)
	}

	return inj, inj.Continue()
}

func (inj *Injector) GetRegisters() (*Registers, error) {
	var regs Registers
	err := syscall.PtraceGetRegs(inj.pid, (*syscall.PtraceRegs)(&regs))
	return &regs, err
}

func (inj *Injector) SetRegisters(regs *Registers) error {
	return syscall.PtraceSetRegs(inj.pid, (*syscall.PtraceRegs)(regs))
}

func (inj *Injection) WaitForBreakpoint() error {
	var ws syscall.WaitStatus
	for {
		_, err := syscall.Wait4(-1*inj.pgid, &ws, 0, nil)
		if err != nil {
			return err
		}
		if ws.Exited() || ws.CoreDump() {
			return fmt.Errorf("target process exited unexpectedly")
		}
		if ws.StopSignal() == syscall.SIGSEGV {
			return fmt.Errorf("target process segfaulted")
		}
		if ws.StopSignal() == syscall.SIGTRAP {
			break
		}
	}
	return nil
}

func (inj *Injection) Continue() error {
	return syscall.PtraceCont(inj.pid, 0)
}

func (inj *Injection) Close() error {
	_, err := syscall.PtracePokeData(inj.pid, inj.injectionAddress, inj.originalCode)
	if err != nil {
		return fmt.Errorf("could not restore original program code, reason: %w", err)
	}
	err = syscall.PtraceSetRegs(inj.pid, &inj.originalRegisters)
	if err != nil {
		return fmt.Errorf("could not restore original registers, reason: %w", err)
	}
	return nil
}

type PageCleaner struct {
	inj *Injector
}

func NewPageCleaner(process Process) (*PageCleaner, error) {
	inj, err := NewInjector(process)
	if err != nil {
		return nil, err
	}
	return &PageCleaner{
		inj: inj,
	}, nil
}

func (pc *PageCleaner) Snapshot(seg *MemorySegmentInfo) (*PageStateSnapshot, error) {
	pageCount := (seg.Size + pageSize - 1) / pageSize

	stateVecAddr, err := pc.snapshotAllocateRemoteMemory(pageCount)
	if err != nil {
		return nil, fmt.Errorf("could not allocate remote memory, reason: %w", err)
	}

	stateVec, err := pc.getMincoreStateVector(seg.BaseAddress, seg.Size, stateVecAddr, pageCount)
	if err != nil {
		return nil, fmt.Errorf("could not get remote mincore information, reason: %w", err)
	}

	return &PageStateSnapshot{
		inj:   pc.inj,
		state: stateVec,
	}, nil
}

func (pc *PageCleaner) snapshotAllocateRemoteMemory(length uintptr) (uintptr, error) {
	code := NewAssembler().
		MmapAnonymous(length, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE).
		Int3().
		Assemble()

	var regs *Registers
	var err error
	out := pc.inj.RunRemoteCode(code, 1)
	for result := range out {
		if result.IsErr() {
			err = result.Err()
			break
		} else {
			regs = result.Registers()
		}
	}
	if err != nil {
		err = errors.NewMultiError(err, pc.inj.WaitForRemoteCodeFinish(out))
		return 0, fmt.Errorf("could not allocate remote memory, reason: %w", err)
	}
	if regs == nil {
		return 0, fmt.Errorf("could not allocate remote memory, reason: registers missing unexpectedly, this should never happen")
	}

	allocatedAddr := int64(regs.Rax)
	if allocatedAddr < 0 {
		return 0, fmt.Errorf("could not allocate remote memory, error code: %d", -allocatedAddr)
	}
	return uintptr(allocatedAddr), nil
}

func (pc *PageCleaner) getMincoreStateVector(mincoreAddress, mincoreLength uintptr, stateVecAddr uintptr, vecLength uintptr) ([]byte, error) {
	code := NewAssembler().
		Mincore(mincoreAddress, mincoreLength, stateVecAddr).
		Int3().
		Munmap(stateVecAddr, vecLength).
		Int3().
		Assemble()

	var err error
	out := pc.inj.RunRemoteCode(code, 2)
	// Wait for first breakpoint
	for result := range out {
		if result.IsErr() {
			err = result.Err()
		}

		break
	}
	if err != nil {
		err = errors.NewMultiError(err, pc.inj.WaitForRemoteCodeFinish(out))
		return nil, fmt.Errorf("could not get mincore information, reason: %w", err)
	}

	stateVec := make([]byte, vecLength)
	err = pc.inj.ReadMemory(stateVecAddr, stateVec)
	if err != nil {
		err = errors.NewMultiError(err, pc.inj.WaitForRemoteCodeFinish(out))
		return nil, fmt.Errorf("could not read mincore state vector, reason: %w", err)
	}

	return stateVec, pc.inj.WaitForRemoteCodeFinish(out)
}

type PageStateSnapshot struct {
	inj                 *Injector
	sectionStartAddress uintptr
	state               []byte
}

func (s *PageStateSnapshot) Restore() error {
	workPackages := s.makeWorkPackages()

	asm := NewAssembler()
	for _, pkg := range workPackages {
		asm.Madvise(pkg.Address, pkg.Length, syscall.MADV_DONTNEED)
	}

	out := s.inj.RunRemoteCode(asm.Assemble(), 1)
	return s.inj.WaitForRemoteCodeFinish(out)
}

type workPackage struct {
	Address uintptr
	Length  uintptr
}

func (s *PageStateSnapshot) makeWorkPackages() []*workPackage {
	packages := make([]*workPackage, 0)

	var lastPackage *workPackage
	for i, state := range s.state {
		if state == 0 {
			// needs to be advised
			if lastPackage == nil {
				lastPackage = &workPackage{
					Address: s.pageIndexToAddress(i),
					Length:  0,
				}
			}
			lastPackage.Length += pageSize
		} else {
			if lastPackage != nil {
				packages = append(packages, lastPackage)
				lastPackage = nil
			}
		}
	}
	return packages
}

func (s *PageStateSnapshot) pageIndexToAddress(i int) uintptr {
	return s.sectionStartAddress + uintptr(i*pageSize)
}
