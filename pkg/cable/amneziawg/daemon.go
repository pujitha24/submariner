/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package amneziawg

import (
	"fmt"
	"net"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/ipc"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"github.com/pkg/errors"
)

type userspaceDevice interface {
	Close() error
}

// UserspaceDevice manages the embedded amneziawg-go daemon.
type UserspaceDevice = userspaceDevice

// StartUserspaceDeviceForTest overrides userspace device startup in unit tests.
var StartUserspaceDeviceForTest func(ifaceName string) (UserspaceDevice, error)

type embeddedDaemon struct {
	tunDev tun.Device
	dev    *device.Device
	uapi   net.Listener
	wg     sync.WaitGroup
	once   sync.Once
}

func (d *embeddedDaemon) Close() error {
	var err error

	d.once.Do(func() {
		if d.uapi != nil {
			err = d.uapi.Close()
		}

		if d.dev != nil {
			d.dev.Close()
		}

		d.wg.Wait()
	})

	return err
}

var startUserspaceDevice = func(ifaceName string) (userspaceDevice, error) {
	tdev, err := tun.CreateTUN(ifaceName, device.DefaultMTU)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create TUN device")
	}

	fileUAPI, err := ipc.UAPIOpen(ifaceName)
	if err != nil {
		_ = tdev.Close()
		return nil, errors.Wrap(err, "failed to open UAPI socket")
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", ifaceName))
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	uapi, err := ipc.UAPIListen(ifaceName, fileUAPI)
	if err != nil {
		_ = tdev.Close()
		dev.Close()

		return nil, errors.Wrap(err, "failed to listen on UAPI socket")
	}

	daemon := &embeddedDaemon{
		tunDev: tdev,
		dev:    dev,
		uapi:   uapi,
	}

	daemon.wg.Add(1)

	go func() {
		defer daemon.wg.Done()

		for {
			conn, acceptErr := uapi.Accept()
			if acceptErr != nil {
				return
			}

			go dev.IpcHandle(conn)
		}
	}()

	return daemon, nil
}
