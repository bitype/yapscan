package procIO

import "github.com/0xrawsec/golang-win32/win32"

func SegmentFromMemoryBasicInformation(info win32.MemoryBasicInformation) *MemorySegmentInfo {
	return &MemorySegmentInfo{
		ParentBaseAddress:    uint64(info.AllocationBase),
		BaseAddress:          uint64(info.BaseAddress),
		AllocatedPermissions: permissionsFromProtectDWORD(info.AllocationProtect),
		CurrentPermissions:   permissionsFromProtectDWORD(info.Protect),
		Size:                 uint64(info.RegionSize),
		State:                stateFromDWORD(info.State),
		Type:                 typeFromDWORD(info.Type),
		SubSegments:          make([]*MemorySegmentInfo, 0),
	}
}

func permissionsFromProtectDWORD(protect win32.DWORD) Permissions {
	mp := Permissions{
		Read:    false,
		Write:   false,
		COW:     false,
		Execute: false,
	}

	protect &= win32.DWORD(0xFF)

	switch protect {
	case win32.PAGE_READONLY:
		mp.Read = true
	case win32.PAGE_READWRITE:
		mp.Read = true
		mp.Write = true
	case win32.PAGE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
	case win32.PAGE_EXECUTE:
		mp.Execute = true
	case win32.PAGE_EXECUTE_READ:
		mp.Read = true
		mp.Execute = true
	case win32.PAGE_EXECUTE_READWRITE:
		mp.Read = true
		mp.Write = true
		mp.Execute = true
	case win32.PAGE_EXECUTE_WRITECOPY:
		mp.Read = true
		mp.Write = true
		mp.COW = true
		mp.Execute = true
	}

	return mp
}

func stateFromDWORD(state win32.DWORD) State {
	switch state {
	case win32.MEM_COMMIT:
		return StateCommit
	case win32.MEM_FREE:
		return StateFree
	case win32.MEM_RESERVE:
		return StateReserve
	}
	return State(state)
}

func typeFromDWORD(t win32.DWORD) Type {
	switch t {
	case win32.DWORD(0x1000000):
		return TypeImage
	case win32.MEM_MAPPED:
		return TypeMapped
	case win32.MEM_PRIVATE:
		return TypePrivate
	}
	return Type(t)
}
