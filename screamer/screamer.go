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

// Package screamer provides low-level TLP interface for a PCIe screamer device.
// Based on:
// https://github.com/ufrisk/LeechCore/blob/master/leechcore/fpga_libusb.c
// https://github.com/ufrisk/LeechCore/blob/master/leechcore/device_fpga.c

package screamer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	"github.com/google/gousb"
)

const (
	// Screamer USB identifiers.
	// "ID 0403:601f Future Technology Devices International, Ltd"
	ftdiVendorID  = 0x0403
	ftdiProductID = 0x601f

	// Screamer PCIe identifiers.
	// "Ethernet controller: Xilinx Corporation Device 0666"
	screamerVID = 0x10ee
	screamerPID = 0x0666

	screamerSessionInterfaceNum        = 0
	screamerSessionInterfaceAltSetting = 0
	screamerSessionOutEndpoint         = 1

	screamerDataInterfaceNum        = 1
	screamerDataInterfaceAltSetting = 0
	screamerDataInEndpoint          = 0x82
	screamerDataOutEndpoint         = 2

	// v4 bitstream can be downloaded from
	// https://github.com/ufrisk/pcileech-fpga/tree/master/pciescreamer
	screamerFPGAVersion = 4
	screamerFPGAID      = 3
)

const (
	rTypeControlIn  uint8 = gousb.ControlIn | gousb.ControlVendor | gousb.ControlInterface
	rTypeControlOut uint8 = gousb.ControlOut | gousb.ControlVendor | gousb.ControlInterface
)

const (
	reqChipConfiguration uint8 = 0xcf
)

type ft60xConfiguration struct {
	VendorID                  uint16
	ProductID                 uint16
	StringDescriptors         [128]byte
	Reserved                  uint8
	PowerAttributes           uint8
	PowerConsumption          uint16
	Reserved2                 uint8
	FIFOClock                 uint8
	FIFOMode                  uint8
	ChannelConfig             uint8
	OptionalFeatureSupport    uint16
	BatteryChargingGPIOConfig uint8
	FlashEEPROMDetection      uint8
	MSIOControl               uint32
	GPIOControl               uint32
}

// ft60xConfiguration consts
const (
	// FIFOMode
	confFIFOMode245 uint8 = 0
	confFIFOMode600 uint8 = 1

	// ChannelConfig
	confChannelConfig4        uint8 = 0
	confChannelConfig2        uint8 = 1
	confChannelConfig1        uint8 = 2
	confChannelConfig1OutPipe uint8 = 3
	confChannelConfig1InPipe  uint8 = 4

	// OptionalFeatureSupport
	confOptionalFeatureSupprtDisableAll            uint16 = 0
	confOptionalFeatureSupprtEnableBatteryCharging uint16 = 1

	// reqChipConfiguration values
	getChipConfigurationValue     = 1
	getChipConfigurationZeroIndex = 0
	setChipConfigurationValue     = 0
	setChipConfigurationZeroIndex = 0
)

// controlRequest specifies a control command and sent over
// the session OUT endpoint.
// Based on struct ft60x_ctrlreq.
type controlRequest struct {
	idx  uint32
	pipe uint8
	cmd  uint8
	unk1 uint8
	unk2 uint8
	len  uint32
	unk4 uint32
	unk5 uint32
}

const ctrlReqReadCmd uint8 = 1

type configFlags uint16

const (
	configFlagPcie      configFlags = 0x0001
	configFlagCore      configFlags = 0x0003
	configFlagReadOnly  configFlags = 0x0000
	configFlagReadWrite configFlags = 0x8000
)

const (
	maxConfigAddr      = 0x1000
	maxConfigReadSize  = 0x1000
	maxConfigWriteSize = 0x200
	maxConfigResponse  = 0x20000
	configTargetRead   = 0x10
	configTargetWrite  = 0x20
	configRequestMagic = 0x77

	statusPropertiesMask = 0xf0000000
	statusWithDataBlocks = 0xe0000000
)

type fpgaVersion struct {
	VersionMajor uint8
	VersionMinor uint8
	FPGAID       uint8
}

const fpgaVersionAddr = 0x0008

const (
	inactivityTimerValue = 100000 // 1ms ( 100000 * 100MHz )
	inactivityTimerAddr  = 0x0008
)

const deviceIDAddr = 0x0008

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

func (ver *fpgaVersion) isSupported() bool {
	return ver.VersionMajor == screamerFPGAVersion && ver.FPGAID >= screamerFPGAID
}

const (
	readTimeout  = 100 * time.Millisecond
	writeTimeout = 100 * time.Millisecond
)

const dwordLen = 4

// Max TX/RX sizes copied from PERFORMANCE_PROFILES array.
const (
	maxReceiveSize  = 0x1c000
	maxTransmitSize = 0x1000
)

// Following values were copied from DeviceFPGA_TxTlp().
var (
	txTLPDataCommand = []byte{0x00, 0x00, 0x00, 0x77}
	txTLPValidLast   = []byte{0x00, 0x00, 0x04, 0x77}
	txTLPLoopback    = []byte{0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, 0x02, 0x77}
)

const (
	readTLPLastMask        = 7
	readTLPPCIeAndLastData = 4
)

type dword [4]uint8

type dataBlock struct {
	Status uint32
	Data   [7]dword
}

// errors
var (
	ErrUSBOpenFailed          = errors.New("failed claiming USB resources")
	ErrDeviceConfigFailed     = errors.New("failed configuring device")
	ErrUnsupportedVersion     = errors.New("unsupported FPGA version")
	ErrSettingInactivityTimer = errors.New("failed setting inactivity timer")
	ErrReadingDeviceAddress   = errors.New("failed reading device address")
)

// abbreviations
var (
	be = binary.BigEndian
	le = binary.LittleEndian
)

// sharedUSBContext manages a refcount for given gousb.Context object.
// This allows sharing a single context by multiple Screamer devices.
// Context is automatically closed once all references are dropped.
type sharedUSBContext struct {
	usbCtx   usbContext
	refCount int32
}

func newUSBContext() *sharedUSBContext {
	return &sharedUSBContext{
		usbCtx:   newUSBContextAdapter(gousb.NewContext()),
		refCount: 1,
	}
}

func (c *sharedUSBContext) Ref() *sharedUSBContext {
	atomic.AddInt32(&c.refCount, 1)
	return c
}

func (c *sharedUSBContext) Close() {
	if atomic.AddInt32(&c.refCount, -1) == 0 {
		glog.V(1).Infof("Closing usb context")
		c.usbCtx.Close()
		c.usbCtx = nil
	}
}

// Screamer encapsulates device's USB resources.
type Screamer struct {
	ctx *sharedUSBContext
	// dev also implements the control endpoint.
	dev usbDevice
	cfg usbConfig
	// Session list output endpoint.
	sessInt   usbInterface
	sessOutEp usbOutEndpoint
	// Data output/input endpoints.
	dataInt   usbInterface
	dataOutEp usbOutEndpoint
	dataInEp  usbInEndpoint
	// Configuration space address that uniquely identifies the device on the
	// PCIe fabric.
	deviceID uint16
}

// openScreamer claims USB interfaces and opens communication endpoints.
// Based on fpga_open().
// Takes ownership of rawDev.
func openScreamer(rawDev usbDevice, ctx *sharedUSBContext) (*Screamer, error) {
	glog.Infof("Opening screamer device %v", rawDev)
	d := &Screamer{
		ctx: ctx.Ref(),
		dev: rawDev,
	}

	var failed = true
	defer func() {
		if failed {
			d.Close()
		}
	}()

	if err := d.claimUSBResources(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUSBOpenFailed, err)
	}
	if err := d.configure(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeviceConfigFailed, err)
	}
	ver, err := d.readFPGAVersion()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedVersion, err)
	}
	if !ver.isSupported() {
		return nil, fmt.Errorf("%w: %+v", ErrUnsupportedVersion, ver)
	}
	if err = d.setInactivityTimer(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSettingInactivityTimer, err)
	}
	d.deviceID, err = d.readDeviceAddress()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrReadingDeviceAddress, err)
	}
	failed = false
	return d, nil
}

func (d *Screamer) claimUSBResources() error {
	cfgNum, err := d.dev.ActiveConfigNum()
	if err != nil {
		return fmt.Errorf("failed to get active config number of device %s: %v", d.dev, err)
	}
	d.cfg, err = d.dev.Config(cfgNum)
	if err != nil {
		return fmt.Errorf("failed to claim config %d of device %s: %v", cfgNum, d.dev, err)
	}
	d.sessInt, err = d.cfg.Interface(screamerSessionInterfaceNum, screamerSessionInterfaceAltSetting)
	if err != nil {
		return fmt.Errorf("failed to select interface #%d alternate setting %d of config %d of device %s: %v", screamerSessionInterfaceNum, screamerSessionInterfaceAltSetting, cfgNum, d.dev, err)
	}
	d.sessOutEp, err = d.sessInt.OutEndpoint(screamerSessionOutEndpoint)
	if err != nil {
		return fmt.Errorf("failed to open session output endpoint: %v", err)
	}
	d.dataInt, err = d.cfg.Interface(screamerDataInterfaceNum, screamerDataInterfaceAltSetting)
	if err != nil {
		return fmt.Errorf("failed to select interface #%d alternate setting %d of config %d of device %s: %v", screamerDataInterfaceNum, screamerDataInterfaceAltSetting, cfgNum, d.dev, err)
	}
	d.dataOutEp, err = d.dataInt.OutEndpoint(screamerDataOutEndpoint)
	if err != nil {
		return fmt.Errorf("failed to open data output endpoint: %v", err)
	}
	d.dataInEp, err = d.dataInt.InEndpoint(screamerDataInEndpoint)
	if err != nil {
		return fmt.Errorf("failed to open data input endpoint: %v", err)
	}
	return nil
}

func (d *Screamer) getChipConfiguration(conf *ft60xConfiguration) error {
	buf := make([]byte, binary.Size(conf))
	if n, err := d.dev.Control(rTypeControlIn, reqChipConfiguration, getChipConfigurationValue, getChipConfigurationZeroIndex, buf); err != nil || n != len(buf) {
		return fmt.Errorf("dev.Control(rTypeControlIn, reqChipConfiguration, 1, 0, %X) = %v, %v, want n=%d and nil error", buf, n, err, len(buf))
	}
	r := bytes.NewReader(buf)
	if err := binary.Read(r, le, conf); err != nil {
		return fmt.Errorf("binary.Read(%X, le, conf) = %v, want nil error", buf, err)
	}
	return nil
}

func (d *Screamer) setChipConfiguration(conf *ft60xConfiguration) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, le, conf); err != nil {
		return fmt.Errorf("binary.Write(buf, le, %X) = %v, want nil error", conf, err)
	}
	if n, err := d.dev.Control(rTypeControlOut, reqChipConfiguration, setChipConfigurationValue, setChipConfigurationZeroIndex, buf.Bytes()); err != nil || n != buf.Len() {
		return fmt.Errorf("dev.Control(rTypeControlOut, reqChipConfiguration, 0, 0) = %v, %v, want n=%d and nil error", n, err, buf.Len())
	}
	return nil
}

// configure sets chip configuration.
// Based on fpga_open() and DeviceFPGA_GetDeviceID_FpgaVersionV4().
func (d *Screamer) configure() error {
	var chip ft60xConfiguration
	if err := d.getChipConfiguration(&chip); err != nil {
		return fmt.Errorf("getChipConfiguration() = %v, want nil error", err)
	}
	glog.V(1).Infof("Chip configuration: %+v", chip)
	if chip.FIFOMode == confFIFOMode245 &&
		chip.ChannelConfig == confChannelConfig1 &&
		chip.OptionalFeatureSupport == confOptionalFeatureSupprtDisableAll {
		return nil
	}

	glog.Warningf("Bad FTDI configuration. Setting chip config to FIFO 245 && 1 channel, no feature support")
	chip.FIFOMode = confFIFOMode245
	chip.ChannelConfig = confChannelConfig1
	chip.OptionalFeatureSupport = confOptionalFeatureSupprtDisableAll
	return d.setChipConfiguration(&chip)
}

// buildDataReadRequest builds a data-read command, requesting up to |size|
// bytes of data from data IN endpoint.
// Based on ftdi_SendCmdRead().
func buildDataReadRequest(size int) ([]byte, error) {
	req := controlRequest{
		idx:  1,
		pipe: screamerDataInEndpoint,
		cmd:  ctrlReqReadCmd,
		len:  uint32(size),
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, le, req); err != nil {
		return nil, fmt.Errorf("binary.Write(buf, le, %+v) = %v, want nil error", req, err)
	}
	return buf.Bytes(), nil
}

// dataReadContext reads from data IN endpoint with context.
func (d *Screamer) dataReadContext(ctx context.Context, p []byte) (int, error) {
	n, err := d.dataInEp.ReadContext(ctx, p)
	if err == gousb.TransferCancelled {
		// Special case when read times out. Per https://golang.org/pkg/io/#Reader:
		// "Callers should treat a return of 0 and nil as indicating that nothing happened;
		//  in particular it does not indicate EOF."
		glog.V(2).Infof("Reading from data IN timedout")
		return 0, nil
	}
	return n, err
}

// skipOverFTDIFillers removes 'ffUU' prefixes from |p|.
func skipOverFTDIFillers(p []byte) int {
	i := 0
	n := len(p)
	for i = 0; i+4 <= n; i += 4 {
		if !bytes.Equal(p[i:i+4], []byte{0x66, 0x66, 0x55, 0x55}) {
			break
		}
	}
	copy(p[:n-i], p[i:n])
	return n - i
}

// dataRead submits a read command, and reads from data IN endpoint.
// Based on fpga_read()
func (d *Screamer) dataRead(p []byte) (int, error) {
	// Submit data-read command.
	req, err := buildDataReadRequest(len(p))
	if err != nil {
		return 0, fmt.Errorf("buildDataReadRequest(%d) = %v, want nil error", len(p), err)
	}
	wCtx, wDone := context.WithTimeout(context.TODO(), writeTimeout)
	defer wDone()
	if n, err := d.sessOutEp.WriteContext(wCtx, req); err != nil || n != len(req) {
		return 0, fmt.Errorf("d.sessOutEp.WriteContext(_, %X) = %v, %v, want n=%d and nil error", req, n, err, len(req))
	}

	// Read response with timeout.
	// TODO: pass context from top level functions.
	rCtx, rDone := context.WithTimeout(context.TODO(), readTimeout)
	defer rDone()
	n, err := d.dataReadContext(rCtx, p)
	if err != nil {
		return n, err
	}

	// Remove dummy FTDI fillers. This simplifies processing at the caller.
	n = skipOverFTDIFillers(p[:n])
	glog.V(2).Infof("[DATA-READ]: read %d bytes. data:[:%d]\n%s", n, min(n, 32), hex.Dump(p[:min(n, 32)]))
	return n, err
}

// dataWrite writes |p| to data OUT endpoint.
// Based on fpga_write()
func (d *Screamer) dataWrite(p []byte) (int, error) {
	// Write data with timeout.
	// TODO: pass context from top level functions.
	ctx, done := context.WithTimeout(context.TODO(), writeTimeout)
	defer done()
	n, err := d.dataOutEp.WriteContext(ctx, p)
	if err != nil {
		return n, err
	}

	glog.V(2).Infof("[DATA-WRITE]: wrote %d bytes. data[:%d]:\n%s", n, min(n, 32), hex.Dump(p[:min(n, 32)]))
	return n, err
}

// buildConfigReadRequests builds a list of requests that read |dataLength|
// bytes from FPGA configuration registers starting at |baseAddr|.
func buildConfigReadRequests(baseAddr, dataLength int, flags configFlags) ([]byte, error) {
	type readRequest struct {
		Reserved [4]uint8
		Address  uint16 // In BigEndian.
		Target   uint8
		Magic    uint8
	}

	// Read len(data) bytes from baseAddr in chunks of 2 bytes.
	// This is the granularity of read requests for the FPGA firmware API.
	buf := new(bytes.Buffer)
	for i := 0; i < dataLength; i += 2 {
		req := readRequest{
			Address: uint16((baseAddr + i) | (int(flags) & int(configFlagReadWrite))),
			Target:  uint8(configTargetRead | (int(flags) & int(configFlagCore))),
			Magic:   configRequestMagic,
		}
		if err := binary.Write(buf, be, req); err != nil {
			return nil, fmt.Errorf("binary.Write(buf, be, req) = %v, want nil error", err)
		}
	}
	return buf.Bytes(), nil
}

// parseConfigReadResponse extracts data bytes from |res| and copies them
// into |data|.
// Based on DeviceFPGA_ConfigRead().
func parseConfigReadResponse(res []byte, baseAddr int, flags configFlags, data []byte) (int, error) {
	var d dataBlock
	r := bytes.NewReader(res)
	n := -1
	for r.Len() >= binary.Size(d) {
		if err := binary.Read(r, le, &d); err != nil {
			return 0, fmt.Errorf("binary.Read(r, le, &d) = %v, want nil error", err)
		}
		if (d.Status & statusPropertiesMask) != statusWithDataBlocks {
			continue
		}
		// Status (32bits) encodes information about the attached data blocks in each
		// of its 4bits nibbles.
		// Iterate over each 4b nibble in status, and extract config data bytes.
		for j := 0; j < len(d.Data); j, d.Status = j+1, d.Status>>4 {
			if (int(d.Status) & 0x0f) == (int(flags) & int(configFlagCore)) {
				addr := int(be.Uint16(d.Data[j][0:2]))
				addr -= (int(flags) & int(configFlagReadWrite)) + baseAddr
				if addr >= len(data) {
					return 0, fmt.Errorf("address %x is out of range (%x)", addr, len(data))
				}
				data[addr] = d.Data[j][2]
				n = max(n, addr)
				if addr+1 < len(data) {
					data[addr+1] = d.Data[j][3]
					n = max(n, addr+1)
				}
			}
		}
	}
	// Return bytes read.
	return n + 1, nil
}

// configRead reads from bitstream v4 configuration registers.
// The bitstream has four register spaces, one read-only and one read-write
// for each core and pcie.
// Based on DeviceFPGA_ConfigRead().
func (d *Screamer) configRead(baseAddr int, flags configFlags, data []byte) (int, error) {
	if baseAddr > maxConfigAddr {
		return 0, fmt.Errorf("invalid base address, got %d, want <= maxConfigAddr (%d)", baseAddr, maxConfigAddr)
	}
	if len(data) > maxConfigReadSize {
		return 0, fmt.Errorf("invalid data length, got %d, want <= maxConfigReadSize (%d)", len(data), maxConfigReadSize)
	}

	req, err := buildConfigReadRequests(baseAddr, len(data), flags)
	if err != nil {
		return 0, err
	}

	if n, err := d.dataWrite(req); err != nil || n != len(req) {
		return 0, fmt.Errorf("d.dataWrite(%X) = %v, %v, want n=%d and nil error", req, n, err, len(req))
	}

	res := make([]byte, maxConfigResponse)
	n, err := d.dataRead(res)
	if err != nil {
		return 0, fmt.Errorf("d.dataRead(res) = %v, want nil error", err)
	}

	n, err = parseConfigReadResponse(res[:n], baseAddr, flags, data)
	if err != nil {
		return 0, fmt.Errorf("parseConfigReadResponse(%X, %x, %x, _) = _, %v, want nil error", res[:n], baseAddr, flags, err)
	}
	return n, nil
}

// buildConfigWriteRequests builds a list of requests that write |data|
// bytes to FPGA configuration registers starting at |baseAddr|.
func buildConfigWriteRequests(baseAddr int, flags configFlags, data, mask []byte) ([]byte, error) {
	type writeRequest struct {
		Data    [2]uint8
		Mask    [2]uint8
		Address uint16 // In BigEndian.
		Target  uint8
		Magic   uint8
	}

	if len(data) != len(mask) {
		return nil, fmt.Errorf("len(mask) != len(data), want %d got %d", len(data), len(mask))
	}

	// Write data to baseAddr in chunks of 2 bytes. This is the granularity
	// of write requests for the FPGA firmware API.
	buf := new(bytes.Buffer)
	for i := 0; i < len(data); i += 2 {
		req := writeRequest{
			// addr_high = bit[6:0], write_regbank = bit[7]
			// addr_low
			Address: uint16((baseAddr + i) | (int(flags) & int(configFlagReadWrite))),
			// target = bit[0:1], read = bit[4], write = bit[5]
			Target: uint8(configTargetWrite | (int(flags) & int(configFlagCore))),
			Magic:  configRequestMagic,
		}

		req.Data[0] = uint8(data[i])
		req.Mask[0] = uint8(mask[i])
		if i+1 < len(data) {
			req.Data[1] = uint8(data[i+1])
			req.Mask[1] = uint8(mask[i+1])
		}

		if err := binary.Write(buf, be, req); err != nil {
			return nil, fmt.Errorf("binary.Write(buf, be, req) = %v, want nil error", err)
		}
	}
	return buf.Bytes(), nil
}

// configWrite writes to bitstream v4 configuration registers.
// Based on DeviceFPGA_ConfigWrite().
func (d *Screamer) configWrite(baseAddr int, flags configFlags, data []byte) (int, error) {
	if baseAddr > maxConfigAddr {
		return 0, fmt.Errorf("invalid base address, got %d, want <= maxConfigAddr (%d)", baseAddr, maxConfigAddr)
	}
	if len(data) > maxConfigWriteSize {
		return 0, fmt.Errorf("invalid data length, got %d, want <= maxConfigWriteSize (%d)", len(data), maxConfigWriteSize)
	}

	mask := make([]byte, len(data))
	for i := 0; i < len(mask); i++ {
		mask[i] = 0xff
	}

	req, err := buildConfigWriteRequests(baseAddr, flags, data, mask)
	if err != nil {
		return 0, err
	}

	if n, err := d.dataWrite(req); err != nil || n != len(req) {
		return 0, fmt.Errorf("d.dataWrite(%X) = %v, %v, want n=%d and nil error", req, n, err, len(req))
	}
	return len(data), nil
}

// readFPGAVersion reads version information from firmware config registers.
// Based on DeviceFPGA_GetDeviceID_FpgaVersion()
func (d *Screamer) readFPGAVersion() (*fpgaVersion, error) {
	var ver fpgaVersion

	buf := make([]byte, binary.Size(ver))
	if n, err := d.configRead(fpgaVersionAddr, configFlagCore|configFlagReadOnly, buf); err != nil || n != len(buf) {
		return nil, fmt.Errorf("d.configRead(fpgaVersionAddr, configFlagCore|configFlagReadOnly, buf) = %v, %v, want n=%d and nil error", n, err, len(buf))
	}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, le, &ver); err != nil {
		return nil, fmt.Errorf("binary.Read(%X, le, ver) = %v, want nil error", buf, err)
	}
	glog.V(1).Infof("FPGA version: %+v", ver)
	return &ver, nil
}

// setInactivityTimer sets inactivity timer to a useful value.
// Based on DeviceFPGA_GetDeviceID_FpgaVersionV4().
func (d *Screamer) setInactivityTimer() error {
	b := make([]byte, 4)
	le.PutUint32(b, inactivityTimerValue)
	if n, err := d.configWrite(inactivityTimerAddr, configFlagCore|configFlagReadWrite, b); err != nil || n != len(b) {
		return fmt.Errorf("d.configWrite(inactivityTimerAddr, configFlagCore|configFlagReadWrite, % X) = %v, %v, want n=%d and nil error", b, n, err, len(b))
	}
	return nil
}

// readDeviceAddress reads the device address (Bus/Device/Function identifier).
// Based on DeviceFPGA_GetDeviceID_FpgaVersionV4().
func (d *Screamer) readDeviceAddress() (uint16, error) {
	var addr uint16

	buf := make([]byte, binary.Size(addr))
	if n, err := d.configRead(deviceIDAddr, configFlagPcie|configFlagReadOnly, buf); err != nil || n != len(buf) {
		return 0, fmt.Errorf("d.configRead(deviceIDAddr, configFlagPcie|configFlagReadOnly, buf) = %v, %v, want n=%d and nil error", n, err, len(buf))
	}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, be, &addr); err != nil {
		return 0, fmt.Errorf("binary.Read(%X, be, ver) = %v, want nil error", buf, err)
	}
	glog.V(1).Infof("Device address: %X", addr)
	return addr, nil
}

// DeviceID returns |d|'s address.
func (d *Screamer) DeviceID() uint16 {
	return d.deviceID
}

// Close frees device resources.
func (d *Screamer) Close() error {
	glog.V(1).Infof("Closing screamer device")
	if d.dataInt != nil {
		d.dataInt.Close()
		d.dataInt = nil
	}
	if d.sessInt != nil {
		d.sessInt.Close()
		d.sessInt = nil
	}
	if d.cfg != nil {
		d.cfg.Close()
		d.cfg = nil
	}
	if d.dev != nil {
		d.dev.Close()
		d.dev = nil
	}
	if d.ctx != nil {
		d.ctx.Close()
		d.ctx = nil
	}
	return nil
}

// buildWriteTLPCommand builds a TLP write command.
// |tlp| must be dword aligned, and contain at least one dword.
// Based on DeviceFPGA_TxTlp().
func buildWriteTLPCommand(tlp []byte) []byte {
	dwords := make([]dword, len(tlp)/dwordLen)
	for i := 0; i < len(dwords); i++ {
		copy(dwords[i][:], tlp[dwordLen*i:dwordLen*(i+1)])
	}

	buf := new(bytes.Buffer)
	for i := 0; i < len(dwords)-1; i++ {
		buf.Write(dwords[i][:])
		buf.Write(txTLPDataCommand)
	}

	buf.Write(dwords[len(dwords)-1][:])
	buf.Write(txTLPValidLast)

	buf.Write(txTLPLoopback)
	return buf.Bytes()
}

// writeTLP synchronously transmits a TLP buffer.
// p should be dword aligned, and contain at least 3 dwords.
// Based on DeviceFPGA_TxTlp().
func (d *Screamer) writeTLP(p []byte) (int, error) {
	if len(p)%dwordLen > 0 {
		return 0, fmt.Errorf("TLP buffer should be dword aligned, got %d", len(p))
	}
	if len(p) < 3*dwordLen {
		return 0, fmt.Errorf("TLP buffer should contain at least 3 dwords, got %d", len(p))
	}
	if len(p) > maxTransmitSize/2 {
		return 0, fmt.Errorf("TLP buffer too big, want %d, got %d", maxTransmitSize/2, len(p))
	}
	glog.V(1).Infof("[TLP-TX]: sending %d bytes. data:[:%d]\n%s", len(p), min(len(p), 32), hex.Dump(p[:min(len(p), 32)]))
	cmd := buildWriteTLPCommand(p)
	if n, err := d.dataWrite(cmd); err != nil || n != len(cmd) {
		return 0, fmt.Errorf("d.dataWrite(%X) = %v, %v, want n=%d and nil error", cmd, n, err, len(cmd))
	}
	return len(p), nil
}

// parseTLPReadResponse decodes and extracts a single TLP buffer from a TLP
// read response buffer.
// Based on DeviceFPGA_RxTlpSynchronous().
func parseTLPReadResponse(res []byte) ([]byte, error) {
	var d dataBlock
	r := bytes.NewReader(res)
	buf := new(bytes.Buffer)
	var done bool
	for r.Len() >= binary.Size(d) && !done {
		if err := binary.Read(r, le, &d); err != nil {
			return nil, fmt.Errorf("binary.Read(r, le, &d) = %v, want nil error", err)
		}
		if (d.Status & statusPropertiesMask) != statusWithDataBlocks {
			continue
		}
		// Status (32bits) encodes information about the attached data blocks in each
		// of its 4bits nibbles.
		// Iterate over each 4b nibble in status, and extract TLP data bytes.
		for j := 0; j < len(d.Data); j, d.Status = j+1, d.Status>>4 {
			if (int(d.Status) & int(configFlagCore)) == 0x00 {
				// PCIe TLP. Append data to result.
				buf.Write(d.Data[j][:])
			}
			if (int(d.Status) & readTLPLastMask) == readTLPPCIeAndLastData {
				done = true
				break
			}
		}
	}
	return buf.Bytes(), nil
}

// readTLP synchronously reads a TLP buffer.
// Based on DeviceFPGA_RxTlpSynchronous().
func (d *Screamer) readTLP(p []byte) (int, error) {
	// Read encoded TLP buffer.
	res := make([]byte, maxReceiveSize)
	n, err := d.dataRead(res)
	if err != nil {
		return 0, fmt.Errorf("d.dataRead(res) = _, %v, want nil error", err)
	}
	// Decode and extract TLP buffer.
	tlp, err := parseTLPReadResponse(res[:n])
	if err != nil {
		return 0, fmt.Errorf("parseTLPReadResponse(% X) = _, %v, want nil error", res[:n], err)
	}
	// Copy TLP to result buffer.
	n = min(len(p), len(tlp))
	copy(p, tlp[:n])
	glog.V(1).Infof("[TLP-RX]: received %d bytes. data:[:%d]\n%s", n, min(n, 32), hex.Dump(p[:min(n, 32)]))
	return n, nil
}

// TLPController sends and receives TLP packets.
// Implements io.ReadWriter.
type TLPController struct {
	d *Screamer
}

func (c *TLPController) Read(p []byte) (int, error) {
	return c.d.readTLP(p)
}

func (c *TLPController) Write(p []byte) (int, error) {
	return c.d.writeTLP(p)
}

// NewTLPController builds a new TLPController which may be used to send
// and receive TLP packets.
// Caller should not use TLPController after calling d.Close().
func NewTLPController(d *Screamer) *TLPController {
	return &TLPController{d: d}
}

// OpenScreamers enumerates and opens all PCIe screamer devices on the system.
// Caller should Close() all returned Screamers.
func OpenScreamers() ([]*Screamer, error) {
	ctx := newUSBContext()
	defer ctx.Close()

	devs, err := ctx.usbCtx.OpenDevices(func(vendor, product uint16) bool {
		return vendor == ftdiVendorID && product == ftdiProductID
	})
	if err != nil {
		return nil, fmt.Errorf("%w: OpenDevices failed: %v", ErrUSBOpenFailed, err)
	}

	var ret []*Screamer
	for _, dev := range devs {
		d, err := openScreamer(dev, ctx)
		if err != nil {
			return nil, err
		}
		ret = append(ret, d)
	}
	return ret, nil
}
