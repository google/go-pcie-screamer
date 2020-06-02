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

// The following adapters wrap gousb structs and provide a pure interface abstraction.
// This decouples the screamer code from gousb, and simplifies its unit tests.

import (
	"context"
	"io"

	"github.com/google/gousb"
)

//
// gousb interfaces.
//

type usbOutEndpoint interface {
	io.Writer
	WriteContext(ctx context.Context, buf []byte) (int, error)
}

type usbInEndpoint interface {
	io.Reader
	ReadContext(ctx context.Context, buf []byte) (int, error)
}

type usbInterface interface {
	io.Closer
	InEndpoint(epNum int) (usbInEndpoint, error)
	OutEndpoint(epNum int) (usbOutEndpoint, error)
}

type usbConfig interface {
	io.Closer
	Interface(num, alt int) (usbInterface, error)
}

type usbDevice interface {
	io.Closer
	ActiveConfigNum() (int, error)
	Config(cfgNum int) (usbConfig, error)
	ConfigDescription(cfg int) (string, error)
	Control(rType, request uint8, val, idx uint16, data []byte) (int, error)
	GetStringDescriptor(descIndex int) (string, error)
	InterfaceDescription(cfgNum, intfNum, altNum int) (string, error)
	Manufacturer() (string, error)
	Product() (string, error)
	Reset() error
	SerialNumber() (string, error)
	SetAutoDetach(autodetach bool) error
}

// OpenerFunc predicate specifies whether to open the device with the given
// vendor and product identifiers.
type OpenerFunc func(vendor, product uint16) bool

type usbContext interface {
	io.Closer
	OpenDevices(opener OpenerFunc) ([]usbDevice, error)
}

//
// Interface adapter.
//
type usbInterfaceAdapter struct {
	gousb.Interface
}

func newUSBInterfaceAdapter(i *gousb.Interface) *usbInterfaceAdapter {
	return &usbInterfaceAdapter{*i}
}

func (i *usbInterfaceAdapter) Close() error {
	i.Interface.Close()
	return nil
}

func (i *usbInterfaceAdapter) InEndpoint(epNum int) (usbInEndpoint, error) {
	return i.Interface.InEndpoint(epNum)
}

func (i *usbInterfaceAdapter) OutEndpoint(epNum int) (usbOutEndpoint, error) {
	return i.Interface.OutEndpoint(epNum)
}

//
// Config adapter.
//
type usbConfigAdapter struct {
	gousb.Config
}

func newUSBConfigAdapter(cfg *gousb.Config) *usbConfigAdapter {
	return &usbConfigAdapter{*cfg}
}

func (c *usbConfigAdapter) Interface(num, alt int) (usbInterface, error) {
	i, err := c.Config.Interface(num, alt)
	if err != nil {
		return nil, err
	}
	return newUSBInterfaceAdapter(i), nil
}

//
// Device adapter.
//
type usbDeviceAdapter struct {
	gousb.Device
}

func newUSBDeviceAdapter(dev *gousb.Device) *usbDeviceAdapter {
	return &usbDeviceAdapter{*dev}
}

func (d *usbDeviceAdapter) Config(cfgNum int) (usbConfig, error) {
	cfg, err := d.Device.Config(cfgNum)
	if err != nil {
		return nil, err
	}
	return newUSBConfigAdapter(cfg), nil
}

//
// Context adapter.
//
type usbContextAdapter struct {
	gousb.Context
}

func newUSBContextAdapter(ctx *gousb.Context) *usbContextAdapter {
	return &usbContextAdapter{*ctx}
}

func (ctx *usbContextAdapter) OpenDevices(opener OpenerFunc) ([]usbDevice, error) {
	devs, err := ctx.Context.OpenDevices(func(desc *gousb.DeviceDesc) bool {
		return opener(uint16(desc.Vendor), uint16(desc.Product))
	})
	if err != nil {
		for _, d := range devs {
			d.Close()
		}
		return nil, err
	}

	var ret []usbDevice
	for _, d := range devs {
		ret = append(ret, newUSBDeviceAdapter(d))
	}
	return ret, nil
}
