// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Copyright (c) 2020 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Code generated by MockGen. DO NOT EDIT.
// Source: interface.go

// Package log is a generated GoMock package.
package log

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	tag "go.temporal.io/server/common/log/tag"
)

// MockLogger is a mock of Logger interface.
type MockLogger struct {
	ctrl     *gomock.Controller
	recorder *MockLoggerMockRecorder
}

// MockLoggerMockRecorder is the mock recorder for MockLogger.
type MockLoggerMockRecorder struct {
	mock *MockLogger
}

// NewMockLogger creates a new mock instance.
func NewMockLogger(ctrl *gomock.Controller) *MockLogger {
	mock := &MockLogger{ctrl: ctrl}
	mock.recorder = &MockLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLogger) EXPECT() *MockLoggerMockRecorder {
	return m.recorder
}

// DPanic mocks base method.
func (m *MockLogger) DPanic(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "DPanic", varargs...)
}

// DPanic indicates an expected call of DPanic.
func (mr *MockLoggerMockRecorder) DPanic(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DPanic", reflect.TypeOf((*MockLogger)(nil).DPanic), varargs...)
}

// Debug mocks base method.
func (m *MockLogger) Debug(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debug", varargs...)
}

// Debug indicates an expected call of Debug.
func (mr *MockLoggerMockRecorder) Debug(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debug", reflect.TypeOf((*MockLogger)(nil).Debug), varargs...)
}

// Error mocks base method.
func (m *MockLogger) Error(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Error", varargs...)
}

// Error indicates an expected call of Error.
func (mr *MockLoggerMockRecorder) Error(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Error", reflect.TypeOf((*MockLogger)(nil).Error), varargs...)
}

// Fatal mocks base method.
func (m *MockLogger) Fatal(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Fatal", varargs...)
}

// Fatal indicates an expected call of Fatal.
func (mr *MockLoggerMockRecorder) Fatal(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Fatal", reflect.TypeOf((*MockLogger)(nil).Fatal), varargs...)
}

// Info mocks base method.
func (m *MockLogger) Info(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Info", varargs...)
}

// Info indicates an expected call of Info.
func (mr *MockLoggerMockRecorder) Info(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Info", reflect.TypeOf((*MockLogger)(nil).Info), varargs...)
}

// Panic mocks base method.
func (m *MockLogger) Panic(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Panic", varargs...)
}

// Panic indicates an expected call of Panic.
func (mr *MockLoggerMockRecorder) Panic(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Panic", reflect.TypeOf((*MockLogger)(nil).Panic), varargs...)
}

// Warn mocks base method.
func (m *MockLogger) Warn(msg string, tags ...tag.Tag) {
	m.ctrl.T.Helper()
	varargs := []interface{}{msg}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Warn", varargs...)
}

// Warn indicates an expected call of Warn.
func (mr *MockLoggerMockRecorder) Warn(msg interface{}, tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{msg}, tags...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Warn", reflect.TypeOf((*MockLogger)(nil).Warn), varargs...)
}

// MockWithLogger is a mock of WithLogger interface.
type MockWithLogger struct {
	ctrl     *gomock.Controller
	recorder *MockWithLoggerMockRecorder
}

// MockWithLoggerMockRecorder is the mock recorder for MockWithLogger.
type MockWithLoggerMockRecorder struct {
	mock *MockWithLogger
}

// NewMockWithLogger creates a new mock instance.
func NewMockWithLogger(ctrl *gomock.Controller) *MockWithLogger {
	mock := &MockWithLogger{ctrl: ctrl}
	mock.recorder = &MockWithLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWithLogger) EXPECT() *MockWithLoggerMockRecorder {
	return m.recorder
}

// With mocks base method.
func (m *MockWithLogger) With(tags ...tag.Tag) Logger {
	m.ctrl.T.Helper()
	varargs := []interface{}{}
	for _, a := range tags {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "With", varargs...)
	ret0, _ := ret[0].(Logger)
	return ret0
}

// With indicates an expected call of With.
func (mr *MockWithLoggerMockRecorder) With(tags ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "With", reflect.TypeOf((*MockWithLogger)(nil).With), tags...)
}

// MockSkipLogger is a mock of SkipLogger interface.
type MockSkipLogger struct {
	ctrl     *gomock.Controller
	recorder *MockSkipLoggerMockRecorder
}

// MockSkipLoggerMockRecorder is the mock recorder for MockSkipLogger.
type MockSkipLoggerMockRecorder struct {
	mock *MockSkipLogger
}

// NewMockSkipLogger creates a new mock instance.
func NewMockSkipLogger(ctrl *gomock.Controller) *MockSkipLogger {
	mock := &MockSkipLogger{ctrl: ctrl}
	mock.recorder = &MockSkipLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSkipLogger) EXPECT() *MockSkipLoggerMockRecorder {
	return m.recorder
}

// Skip mocks base method.
func (m *MockSkipLogger) Skip(extraSkip int) Logger {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Skip", extraSkip)
	ret0, _ := ret[0].(Logger)
	return ret0
}

// Skip indicates an expected call of Skip.
func (mr *MockSkipLoggerMockRecorder) Skip(extraSkip interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Skip", reflect.TypeOf((*MockSkipLogger)(nil).Skip), extraSkip)
}
