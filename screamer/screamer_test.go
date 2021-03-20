// (c) Ulf Frisk, 2017-2020
// Copyright (C) 2020 Google LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package screamer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gousb"
)

type stubUSBContext struct {
	closed bool
}

func (ctx *stubUSBContext) Close() error {
	ctx.closed = true
	return nil
}

func (ctx *stubUSBContext) OpenDevices(opener OpenerFunc) ([]usbDevice, error) {
	return nil, nil
}

func TestSharedUSBContextReturnsTheSameObject(t *testing.T) {
	stub := &stubUSBContext{}
	c1 := &sharedUSBContext{usbCtx: stub, refCount: 1}
	c2 := c1.Ref()
	if c2 != c1 {
		t.Errorf("sharedUSBContext.Ref did not return the same pointer")
	}
}

func TestSharedUSBContextIsRefCounted(t *testing.T) {
	stub := &stubUSBContext{}
	c1 := &sharedUSBContext{usbCtx: stub, refCount: 1}
	c2 := c1.Ref()
	c3 := c2.Ref()

	c1.Close()
	c2.Close()
	if stub.closed {
		t.Errorf("sharedUSBContext closed too soon")
	}

	c3.Close()
	if !stub.closed {
		t.Errorf("sharedUSBContext did not close when all references dropped")
	}
}

type badControl struct {
	length int
	err    error
}

type stubUSBDevice struct {
	badControlIn  *badControl        // If set, len and error code to return on Control IN.
	cfgIn         ft60xConfiguration // Chip configuration to return on Control IN.
	badControlOut *badControl        // If set, len and error code to return on Control OUT.
	cfgOut        ft60xConfiguration // Chip configuration received on Control OUT.
}

func (d *stubUSBDevice) Close() error {
	return nil
}

func (d *stubUSBDevice) ActiveConfigNum() (int, error) {
	return 0, nil
}

func (d *stubUSBDevice) Config(cfgNum int) (usbConfig, error) {
	return nil, nil
}

func (d *stubUSBDevice) ConfigDescription(cfg int) (string, error) {
	return "", nil
}

func (d *stubUSBDevice) Control(rType, request uint8, val, idx uint16, data []byte) (int, error) {
	if rType&gousb.ControlIn > 0 {
		if d.badControlIn != nil {
			return d.badControlIn.length, d.badControlIn.err
		}
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.LittleEndian, d.cfgIn); err != nil {
			return 0, err
		}
		l := buf.Len()
		if len(data) < l {
			l = len(data)
		}
		copy(data, buf.Bytes()[:l])
		return l, nil
	}
	// rType.gousb.ControlOut
	if d.badControlOut != nil {
		return d.badControlOut.length, d.badControlOut.err
	}
	r := bytes.NewReader(data)
	if err := binary.Read(r, binary.LittleEndian, &d.cfgOut); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (d *stubUSBDevice) GetStringDescriptor(descIndex int) (string, error) {
	return "", nil
}

func (d *stubUSBDevice) InterfaceDescription(cfgNum, intfNum, altNum int) (string, error) {
	return "", nil
}

func (d *stubUSBDevice) Manufacturer() (string, error) {
	return "", nil
}

func (d *stubUSBDevice) Product() (string, error) {
	return "", nil
}

func (d *stubUSBDevice) Reset() error {
	return nil
}

func (d *stubUSBDevice) SerialNumber() (string, error) {
	return "", nil
}

func (d *stubUSBDevice) SetAutoDetach(autodetach bool) error {
	return nil
}

func TestConfigureSetsMode245(t *testing.T) {
	tests := []struct {
		desc string
		conf ft60xConfiguration
	}{
		{desc: "Fails because of unexpected FIFO mode",
			conf: ft60xConfiguration{FIFOMode: confFIFOMode600}},
		{desc: "Fails because of unexpected channel config",
			conf: ft60xConfiguration{FIFOMode: confFIFOMode245, ChannelConfig: confChannelConfig2}},
		{desc: "Fails because of unexpected optional features",
			conf: ft60xConfiguration{FIFOMode: confFIFOMode245, ChannelConfig: confChannelConfig1, OptionalFeatureSupport: confOptionalFeatureSupprtEnableBatteryCharging}},
	}

	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		stub := &stubUSBDevice{cfgIn: test.conf}
		d := &Screamer{dev: stub}
		if err := d.configure(); err != nil {
			t.Errorf("d.configure() = %v, want nil error", err)
		}
		if stub.cfgOut.FIFOMode != confFIFOMode245 {
			t.Errorf("stub.cfgOut.FIFOMode != confFIFOMode245, got %v", stub.cfgOut.FIFOMode)
		}
		if stub.cfgOut.ChannelConfig != confChannelConfig1 {
			t.Errorf("cfgOut.ChannelConfig != confChannelConfig1, got %v", stub.cfgOut.ChannelConfig)
		}
		if stub.cfgOut.OptionalFeatureSupport != confOptionalFeatureSupprtDisableAll {
			t.Errorf("cfgOut.OptionalFeatureSupport != confOptionalFeatureSupprtDisableAll, got %v", stub.cfgOut.OptionalFeatureSupport)
		}
	}
}

func TestConfigureFailsOnIOErrors(t *testing.T) {
	var config ft60xConfiguration
	tests := []struct {
		desc string
		ctrl *badControl
	}{
		{desc: "Fails because of IO error",
			ctrl: &badControl{length: 0, err: fmt.Errorf("IO error")}},
		{desc: "Fails because of truncated transfer",
			ctrl: &badControl{length: binary.Size(config) - 1, err: nil}},
	}
	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		stub := &stubUSBDevice{badControlIn: test.ctrl}
		d := &Screamer{dev: stub}
		if err := d.configure(); err == nil {
			t.Errorf("d.configure() = %v, want non-nil error", err)
		}

		stub = &stubUSBDevice{badControlOut: test.ctrl}
		d = &Screamer{dev: stub}
		if err := d.configure(); err == nil {
			t.Errorf("d.configure() = %v, want non-nil error", err)
		}
	}
}

func TestFTDIFillersAreSkipped(t *testing.T) {
	tests := []struct {
		desc string
		in   []byte
		want []byte
	}{
		{desc: "Empty buffer",
			in:   []byte{},
			want: []byte{},
		},
		{desc: "No matching prefix",
			in:   []byte{0x11, 0x22, 0x33, 0x44},
			want: []byte{0x11, 0x22, 0x33, 0x44},
		},
		{desc: "Partial FTDI prefix is not removed",
			in:   []byte{0x66, 0x66, 0x55},
			want: []byte{0x66, 0x66, 0x55},
		},
		{desc: "Single FTDI prefix is removed",
			in:   []byte{0x66, 0x66, 0x55, 0x55},
			want: []byte{},
		},
		{desc: "Single FTDI prefix with data",
			in:   []byte{0x66, 0x66, 0x55, 0x55, 0x11, 0x22, 0x33},
			want: []byte{0x11, 0x22, 0x33},
		},
		{desc: "Two FTDI prefixes are removed",
			in:   []byte{0x66, 0x66, 0x55, 0x55, 0x66, 0x66, 0x55, 0x55},
			want: []byte{},
		},
		{desc: "Two FTDI prefixes with data",
			in:   []byte{0x66, 0x66, 0x55, 0x55, 0x66, 0x66, 0x55, 0x55, 0x11, 0x22, 0x33},
			want: []byte{0x11, 0x22, 0x33},
		},
	}
	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		b := make([]byte, len(test.in))
		copy(b, test.in)

		n := skipOverFTDIFillers(b)
		b = b[:n]

		if diff := cmp.Diff(test.want, b); diff != "" {
			t.Errorf("skipOverFTDIFillers() diff -want +got\n%s", diff)
		}
	}
}

func TestDataReadRequestIsSerializedAsExpected(t *testing.T) {
	got, err := buildDataReadRequest(0x1234)
	if err != nil {
		t.Errorf("buildDataReadRequest(0x1234) = _, %v, want nil error", err)
	}

	want := []byte{0x01, 0x00, 0x00, 0x00, // idx
		0x82, // pipe
		0x01, // cmd
		0x00, 0x00,
		0x34, 0x12, // size
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("buildDataReadRequest() diff -want +got\n%s", diff)
	}
}

type stubUSBInEndpoint struct {
	readRes []byte
	readErr error
}

func (ep *stubUSBInEndpoint) Read(p []byte) (int, error) {
	n := min(len(p), len(ep.readRes))
	copy(p, ep.readRes[:n])
	return n, ep.readErr
}

func (ep *stubUSBInEndpoint) ReadContext(ctx context.Context, buf []byte) (int, error) {
	n := min(len(buf), len(ep.readRes))
	copy(buf, ep.readRes[:n])
	return n, ep.readErr
}

func TestReadContextReturnsData(t *testing.T) {
	stub := &stubUSBInEndpoint{readRes: []byte{1, 2, 3}, readErr: nil}
	d := &Screamer{dataInEp: stub}

	ctx, done := context.WithCancel(context.Background())
	defer done()

	b := make([]byte, 10)
	if n, err := d.dataReadContext(ctx, b); err != nil {
		t.Errorf("d.dataReadContext(_) = _, %v, want nil error", err)
	} else if n != 3 {
		t.Errorf("d.dataReadContext(_) = %v, _, want n=3", n)
	} else if diff := cmp.Diff(stub.readRes, b[:n]); diff != "" {
		t.Errorf("d.dataReadContext() diff -want +got\n%s", diff)
	}
}

func TestReadContextReturnsNilOnTimeout(t *testing.T) {
	stub := &stubUSBInEndpoint{readErr: gousb.TransferCancelled}
	d := &Screamer{dataInEp: stub}

	ctx, done := context.WithCancel(context.Background())
	defer done()

	b := make([]byte, 10)
	n, err := d.dataReadContext(ctx, b)

	if !(n == 0 && err == nil) {
		t.Errorf("d.dataReadContext(_) = %v, %v, want 0 and nil error", n, err)
	}
}

func TestBuildConfigReadRequests(t *testing.T) {
	tests := []struct {
		desc       string
		baseAddr   int
		dataLength int
		flags      configFlags
		want       []byte
	}{
		{desc: "Zero data length",
			baseAddr:   0,
			dataLength: 0,
			flags:      0,
			want:       []byte{},
		},
		{desc: "Single data byte ro register",
			baseAddr:   0x120,
			dataLength: 1,
			flags:      configFlagReadOnly,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x10, 0x77},
		},
		{desc: "Two data bytes ro register",
			baseAddr:   0x120,
			dataLength: 2,
			flags:      configFlagReadOnly,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x10, 0x77},
		},
		{desc: "Three data bytes ro register",
			baseAddr:   0x120,
			dataLength: 3,
			flags:      configFlagReadOnly,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x10, 0x77, 0x00, 0x00, 0x00, 0x00, 0x01, 0x22, 0x10, 0x77},
		},
		{desc: "Single data byte rw register",
			baseAddr:   0x120,
			dataLength: 1,
			flags:      configFlagReadWrite,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x81, 0x20, 0x10, 0x77},
		},
		{desc: "Two data bytes rw register",
			baseAddr:   0x120,
			dataLength: 2,
			flags:      configFlagReadWrite,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x81, 0x20, 0x10, 0x77},
		},
		{desc: "Three data bytes rw register",
			baseAddr:   0x120,
			dataLength: 3,
			flags:      configFlagReadWrite,
			want:       []byte{0x00, 0x00, 0x00, 0x00, 0x81, 0x20, 0x10, 0x77, 0x00, 0x00, 0x00, 0x00, 0x81, 0x22, 0x10, 0x77},
		},
	}

	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		got, err := buildConfigReadRequests(test.baseAddr, test.dataLength, test.flags)
		if err != nil {
			t.Errorf("buildConfigReadRequests(%X, %X, %X) = _, %v, want nil error", test.baseAddr, test.dataLength, test.flags, err)
		}
		if diff := cmp.Diff(test.want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("buildConfigReadRequests() diff -want +got\n%s", diff)
		}
	}
}

func TestParseConfigReadResponse(t *testing.T) {
	tests := []struct {
		desc     string
		res      []byte
		baseAddr int
		flags    configFlags
		want     []byte
	}{
		{desc: "Valid FPGA version response",
			// Config response copied off the wire.
			res: []byte{
				0x33, 0xff, 0xff, 0xef, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0a, 0x03, 0x00, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			baseAddr: fpgaVersionAddr,
			flags:    configFlagCore | configFlagReadOnly,
			want:     []byte{4, 0, 3},
		},
		{desc: "Response status without data blocks is skipped. Following version response is successfully returned.",
			// Config response copied off the wire.
			res: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x33, 0xff, 0xff, 0xef, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0a, 0x03, 0x00, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			baseAddr: fpgaVersionAddr,
			flags:    configFlagCore | configFlagReadOnly,
			want:     []byte{4, 0, 3},
		},
	}

	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)

		b := make([]byte, len(test.want))
		if n, err := parseConfigReadResponse(test.res, test.baseAddr, test.flags, b); err != nil {
			t.Errorf("parseConfigReadResponse(%X, %X, %X, _) = _, %v, want nil error", test.res, test.baseAddr, test.flags, err)
		} else if n != len(test.want) {
			t.Errorf("parseConfigReadResponse(%X, %X, %X, _) = %v, _, want n = %d", test.res, test.baseAddr, test.flags, n, len(test.want))
		}
		if diff := cmp.Diff(test.want, b); diff != "" {
			t.Errorf("parseConfigReadResponse() diff -want +got\n%s", diff)
		}
	}
}

func TestParseConfigReadResponseFailsIfOutOfRangeAddress(t *testing.T) {
	// Config response copied off the wire.
	res := []byte{
		0x33, 0xff, 0xff, 0xef, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0a, 0x03, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	b := make([]byte, 2)
	if _, err := parseConfigReadResponse(res, fpgaVersionAddr, configFlagCore|configFlagReadOnly, b); err == nil {
		t.Errorf("parseConfigReadResponse(%X, fpgaVersionAddr,configFlagCore|configFlagReadOnly, _) = _, %v, want non-nil error", res, err)
	}
}

func TestBuildConfigWriteRequests(t *testing.T) {
	tests := []struct {
		desc     string
		baseAddr int
		flags    configFlags
		data     []byte
		mask     []byte
		want     []byte
	}{
		{desc: "Zero data length",
			baseAddr: 0,
			flags:    0,
			data:     []byte{},
			mask:     []byte{},
			want:     []byte{},
		},
		{desc: "Single data byte ro register",
			baseAddr: 0x120,
			flags:    configFlagReadOnly,
			data:     []byte{1},
			mask:     []byte{0xff},
			want:     []byte{0x01, 0x00, 0xff, 0x00, 0x01, 0x20, 0x20, 0x77},
		},
		{desc: "Two data bytes ro register",
			baseAddr: 0x120,
			flags:    configFlagReadOnly,
			data:     []byte{1, 2},
			mask:     []byte{0xff, 0xff},
			want:     []byte{0x01, 0x02, 0xff, 0xff, 0x01, 0x20, 0x20, 0x77},
		},
		{desc: "Three data bytes ro register",
			baseAddr: 0x120,
			flags:    configFlagReadOnly,
			data:     []byte{1, 2, 3},
			mask:     []byte{0xff, 0xff, 0xff},
			want:     []byte{0x01, 0x02, 0xff, 0xff, 0x01, 0x20, 0x20, 0x77, 0x03, 0x00, 0xff, 0x00, 0x01, 0x22, 0x20, 0x77},
		},
		{desc: "Single data byte rw register",
			baseAddr: 0x120,
			flags:    configFlagReadWrite,
			data:     []byte{1},
			mask:     []byte{0xff},
			want:     []byte{0x01, 0x00, 0xff, 0x00, 0x81, 0x20, 0x20, 0x77},
		},
		{desc: "Two data bytes rw register",
			baseAddr: 0x120,
			flags:    configFlagReadWrite,
			data:     []byte{1, 2},
			mask:     []byte{0xff, 0xff},
			want:     []byte{0x01, 0x02, 0xff, 0xff, 0x81, 0x20, 0x20, 0x77},
		},
		{desc: "Three data bytes rw register",
			baseAddr: 0x120,
			flags:    configFlagReadWrite,
			data:     []byte{1, 2, 3},
			mask:     []byte{0xff, 0xff, 0xff},
			want:     []byte{0x01, 0x02, 0xff, 0xff, 0x81, 0x20, 0x20, 0x77, 0x03, 0x00, 0xff, 0x00, 0x81, 0x22, 0x20, 0x77},
		},
	}

	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		got, err := buildConfigWriteRequests(test.baseAddr, test.flags, test.data, test.mask)
		if err != nil {
			t.Errorf("buildConfigWriteRequests(%X, %X, % X, % X) = _, %v, want nil error", test.baseAddr, test.flags, test.data, test.mask, err)
		}
		if diff := cmp.Diff(test.want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("buildConfigWriteRequests() diff -want +got\n%s", diff)
		}
	}
}

func TestFPGAVersionIsSupport(t *testing.T) {
	tests := []struct {
		ver       fpgaVersion
		supported bool
	}{
		{ver: fpgaVersion{VersionMajor: 0, VersionMinor: 0, FPGAID: 0}, supported: false},
		{ver: fpgaVersion{VersionMajor: 4, VersionMinor: 0, FPGAID: 0}, supported: false},
		{ver: fpgaVersion{VersionMajor: 3, VersionMinor: 0, FPGAID: 3}, supported: false},
		{ver: fpgaVersion{VersionMajor: 4, VersionMinor: 0, FPGAID: 3}, supported: true},
		{ver: fpgaVersion{VersionMajor: 5, VersionMinor: 0, FPGAID: 3}, supported: false},
		{ver: fpgaVersion{VersionMajor: 4, VersionMinor: 0, FPGAID: 4}, supported: true},
	}
	for _, test := range tests {
		if test.ver.isSupported() != test.supported {
			t.Errorf("ver %+v isSupported() = %t, want %t", test.ver, test.ver.isSupported(), test.supported)
		}
	}
}

type stubUSBOutEndpoint struct {
}

func (ep *stubUSBOutEndpoint) Write(p []byte) (int, error) {
	return len(p), nil
}

func (ep *stubUSBOutEndpoint) WriteContext(ctx context.Context, buf []byte) (int, error) {
	return len(buf), nil
}

func TestReadDeviceAddress(t *testing.T) {
	// Address config read response copied off the wire.
	res := []byte{
		0x66, 0x66, 0x55, 0x55, 0x66, 0x66, 0x55, 0x55, 0x66, 0x66, 0x55, 0x55, 0x66, 0x66, 0x55, 0x55,
		0x66, 0x66, 0x55, 0x55, 0xf1, 0xff, 0xff, 0xef, 0x00, 0x08, 0x60, 0x00, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	}
	stub := &stubUSBInEndpoint{readRes: res, readErr: nil}
	d := &Screamer{dataInEp: stub, dataOutEp: &stubUSBOutEndpoint{}, sessOutEp: &stubUSBOutEndpoint{}}
	if addr, err := d.readDeviceAddress(); err != nil {
		t.Errorf("d.readDeviceAddress() = %v, want nil error", err)
	} else if addr != 0x6000 {
		t.Errorf("d.readDeviceAddress() = %x, want %x", addr, 0x6000)
	}
}

func TestBuildWriteTLPCommand(t *testing.T) {
	tests := []struct {
		desc string
		tlp  []byte
		want []byte
	}{
		{desc: "TLP with 1 dword",
			tlp: []byte{0xaa, 0xaa, 0xaa, 0xaa},
			want: []byte{
				0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x04, 0x77, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x02, 0x77}},
		{desc: "TLP with 2 dwords",
			tlp: []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb},
			want: []byte{
				0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x77, 0xbb, 0xbb, 0xbb, 0xbb, 0x00, 0x00, 0x04, 0x77,
				0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x02, 0x77}},
		{desc: "TLP with 3 dwords",
			tlp: []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc},
			want: []byte{
				0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x77, 0xbb, 0xbb, 0xbb, 0xbb, 0x00, 0x00, 0x00, 0x77,
				0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x00, 0x04, 0x77, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x02, 0x77}},
	}
	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)
		got := buildWriteTLPCommand(test.tlp)
		if diff := cmp.Diff(test.want, got); diff != "" {
			t.Errorf("buildWriteTLPCommand(% X) diff -want +got\n%s", test.tlp, diff)
		}
	}
}

func TestParseTLPReadResponse(t *testing.T) {
	tests := []struct {
		desc string
		res  []byte
		want []byte
	}{
		{desc: "Empty response",
			res:  []byte{},
			want: []byte{},
		},
		{desc: "MRd response copied off the wire",
			res: []byte{
				0xf2, 0xff, 0xff, 0xef, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0xe0, 0x4a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x60, 0x00, 0x80, 0x00,
				0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x61,
				0x00, 0x40, 0xff, 0xef, 0x62, 0x6f, 0x72, 0x74, 0x00, 0x67, 0x72, 0x75, 0x62, 0x5f, 0x62, 0x69,
				0x6f, 0x73, 0x5f, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
			want: []byte{
				0x4a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x60, 0x00, 0x80, 0x00, 0x20, 0x74, 0x68, 0x61,
				0x6e, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x61, 0x62, 0x6f, 0x72, 0x74,
				0x00, 0x67, 0x72, 0x75, 0x62, 0x5f, 0x62, 0x69, 0x6f, 0x73, 0x5f, 0x69,
			},
		},
		{desc: "Multiple TLP packets in a single response buffer. Only the first TLP is returned.",
			res: []byte{
				0xf2, 0xff, 0xff, 0xef, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0xe0, 0x4a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x60, 0x00, 0x80, 0x00,
				0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x61,
				0x00, 0x40, 0xff, 0xef, 0x62, 0x6f, 0x72, 0x74, 0x00, 0x67, 0x72, 0x75, 0x62, 0x5f, 0x62, 0x69,
				0x6f, 0x73, 0x5f, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xf2, 0xff, 0xff, 0xef, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				0x00, 0x00, 0x00, 0xe0, 0x4a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x60, 0x00, 0x80, 0x00,
				0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x61,
				0x00, 0x40, 0xff, 0xef, 0x62, 0x6f, 0x72, 0x74, 0x00, 0x67, 0x72, 0x75, 0x62, 0x5f, 0x62, 0x69,
				0x6f, 0x73, 0x5f, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			},
			want: []byte{
				0x4a, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x20, 0x60, 0x00, 0x80, 0x00, 0x20, 0x74, 0x68, 0x61,
				0x6e, 0x20, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65, 0x64, 0x00, 0x61, 0x62, 0x6f, 0x72, 0x74,
				0x00, 0x67, 0x72, 0x75, 0x62, 0x5f, 0x62, 0x69, 0x6f, 0x73, 0x5f, 0x69,
			},
		},
	}

	for _, test := range tests {
		t.Logf("Start case: %s", test.desc)

		got, err := parseTLPReadResponse(test.res)
		if err != nil {
			t.Errorf("parseTLPReadResponse(%X, _) = %v, want nil error", test.res, err)
		}
		if diff := cmp.Diff(test.want, got, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("parseTLPReadResponse() diff -want +got\n%s", diff)
		}
	}
}
