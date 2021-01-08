// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package yapscan

import (
	procIO "github.com/fkie-cad/yapscan/procIO"
	mock "github.com/stretchr/testify/mock"
)

// MockMemorySegmentFilterFunc is an autogenerated mock type for the MemorySegmentFilterFunc type
type MockMemorySegmentFilterFunc struct {
	mock.Mock
}

// Execute provides a mock function with given fields: info
func (_m *MockMemorySegmentFilterFunc) Execute(info *procIO.MemorySegmentInfo) bool {
	ret := _m.Called(info)

	var r0 bool
	if rf, ok := ret.Get(0).(func(*procIO.MemorySegmentInfo) bool); ok {
		r0 = rf(info)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}
