// Code generated by mockery v2.40.2. DO NOT EDIT.

package mocks

import (
	internal "github.com/blocky/nitrite/internal"
	mock "github.com/stretchr/testify/mock"

	x509 "crypto/x509"
)

// InternalExtractRootsFunc is an autogenerated mock type for the ExtractRootsFunc type
type InternalExtractRootsFunc struct {
	mock.Mock
}

type InternalExtractRootsFunc_Expecter struct {
	mock *mock.Mock
}

func (_m *InternalExtractRootsFunc) EXPECT() *InternalExtractRootsFunc_Expecter {
	return &InternalExtractRootsFunc_Expecter{mock: &_m.Mock}
}

// Execute provides a mock function with given fields: rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts
func (_m *InternalExtractRootsFunc) Execute(rootsZIPBytes []byte, rootsDigestHex string, unzipAWSRootCerts internal.UnzipAWSRootCertsFunc) (*x509.CertPool, error) {
	ret := _m.Called(rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts)

	if len(ret) == 0 {
		panic("no return value specified for Execute")
	}

	var r0 *x509.CertPool
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte, string, internal.UnzipAWSRootCertsFunc) (*x509.CertPool, error)); ok {
		return rf(rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts)
	}
	if rf, ok := ret.Get(0).(func([]byte, string, internal.UnzipAWSRootCertsFunc) *x509.CertPool); ok {
		r0 = rf(rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*x509.CertPool)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte, string, internal.UnzipAWSRootCertsFunc) error); ok {
		r1 = rf(rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InternalExtractRootsFunc_Execute_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Execute'
type InternalExtractRootsFunc_Execute_Call struct {
	*mock.Call
}

// Execute is a helper method to define mock.On call
//   - rootsZIPBytes []byte
//   - rootsDigestHex string
//   - unzipAWSRootCerts internal.UnzipAWSRootCertsFunc
func (_e *InternalExtractRootsFunc_Expecter) Execute(rootsZIPBytes interface{}, rootsDigestHex interface{}, unzipAWSRootCerts interface{}) *InternalExtractRootsFunc_Execute_Call {
	return &InternalExtractRootsFunc_Execute_Call{Call: _e.mock.On("Execute", rootsZIPBytes, rootsDigestHex, unzipAWSRootCerts)}
}

func (_c *InternalExtractRootsFunc_Execute_Call) Run(run func(rootsZIPBytes []byte, rootsDigestHex string, unzipAWSRootCerts internal.UnzipAWSRootCertsFunc)) *InternalExtractRootsFunc_Execute_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte), args[1].(string), args[2].(internal.UnzipAWSRootCertsFunc))
	})
	return _c
}

func (_c *InternalExtractRootsFunc_Execute_Call) Return(_a0 *x509.CertPool, _a1 error) *InternalExtractRootsFunc_Execute_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *InternalExtractRootsFunc_Execute_Call) RunAndReturn(run func([]byte, string, internal.UnzipAWSRootCertsFunc) (*x509.CertPool, error)) *InternalExtractRootsFunc_Execute_Call {
	_c.Call.Return(run)
	return _c
}

// NewInternalExtractRootsFunc creates a new instance of InternalExtractRootsFunc. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewInternalExtractRootsFunc(t interface {
	mock.TestingT
	Cleanup(func())
}) *InternalExtractRootsFunc {
	mock := &InternalExtractRootsFunc{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
