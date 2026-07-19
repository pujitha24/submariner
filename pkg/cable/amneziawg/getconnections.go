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
	"strconv"
	"time"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/pkg/errors"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	k8snet "k8s.io/utils/net"
)

func (w *amneziawgDriver) GetConnections() ([]v1.Connection, error) {
	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find device %s", DefaultDeviceName)
	}

	connections := make([]v1.Connection, 0)

	for i := range d.Peers {
		key := d.Peers[i].PublicKey

		connection := w.connectionByKey(&key)
		if connection == nil {
			logger.Warningf("Found unknown peer with key %s, removing", key)

			if err := w.removePeer(&key); err != nil {
				logger.Errorf(err, "Could not delete AmneziaWG peer with key %s, ignoring", key)
			}

			continue
		}

		w.updateConnectionForPeer(&d.Peers[i], connection)
		connections = append(connections, *connection.DeepCopy())
	}

	return connections, nil
}

func (w *amneziawgDriver) connectionByKey(key *wgtypes.Key) *v1.Connection {
	for i := range w.connections {
		k, _ := keyFromSpec(&w.connections[i].Endpoint)
		if key.String() == k.String() {
			return w.connections[i]
		}
	}

	return nil
}

func (w *amneziawgDriver) updateConnectionForPeer(p *wgtypes.Peer, connection *v1.Connection) {
	now := int64(time.Nanosecond) * time.Now().UnixNano() / int64(time.Millisecond)
	keepAliveMS := KeepAliveInterval.Milliseconds() + 2

	lc := peerTrafficDelta(connection, lastChecked, now)
	if lc < keepAliveMS {
		return
	}

	tx := peerTrafficDelta(connection, transmitBytes, p.TransmitBytes)
	rx := peerTrafficDelta(connection, receiveBytes, p.ReceiveBytes)
	lcSec := time.Duration(int64(time.Millisecond) * lc).Seconds()

	connectionFamily := connection.GetFamily()

	if p.LastHandshakeTime.IsZero() {
		if lc > HandshakeTimeout.Milliseconds() {
			connection.SetStatus(v1.ConnectionError, "no initial handshake for %.1f seconds", lcSec)
			cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(connection.Status), false, connectionFamily)
		} else if tx > 0 || rx > 0 {
			connection.SetStatus(v1.Connecting, "no initial handshake yet")
			cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(connection.Status), false, connectionFamily)
		}

		return
	}

	if tx > 0 || rx > 0 {
		connection.SetStatus(v1.Connected, "Rx=%d Bytes, Tx=%d Bytes", p.ReceiveBytes, p.TransmitBytes)
		cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(connection.Status), false, connectionFamily)
		saveAndRecordPeerTraffic(&w.localEndpoint, &connection.Endpoint, now, p.TransmitBytes, p.ReceiveBytes, connectionFamily)

		return
	}

	handshakeDelta := time.Since(p.LastHandshakeTime)

	if handshakeDelta > HandshakeTimeout {
		connection.SetStatus(v1.ConnectionError, "no handshake for %.1f seconds",
			handshakeDelta.Seconds())
		cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(connection.Status), false, connectionFamily)

		return
	}

	if lc < 2*keepAliveMS {
		logger.Warningf("No traffic for %.1f seconds; handshake was %.1f seconds ago: %#v", lcSec, handshakeDelta.Seconds(), connection)
		return
	}

	connection.SetStatus(v1.ConnectionError, "no bytes sent or received for %.1f seconds",
		lcSec)
	cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(connection.Status), false, connectionFamily)
}

func (w *amneziawgDriver) updatePeerStatus(c *v1.Connection, key *wgtypes.Key) {
	p, err := w.peerByKey(key)
	if err != nil {
		c.SetStatus(v1.ConnectionError, "cannot fetch status for peer %s: %v", key, err)
		cable.RecordConnection(cableDriverName, &w.localEndpoint, &c.Endpoint, string(c.Status), false, c.GetFamily())

		return
	}

	w.updateConnectionForPeer(p, c)
}

func peerTrafficDelta(c *v1.Connection, key string, newVal int64) int64 {
	s, found := c.Endpoint.BackendConfig[key]
	if found {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return newVal - i
		}
	}

	c.Endpoint.BackendConfig[key] = strconv.FormatInt(newVal, 10)

	return 0
}

func saveAndRecordPeerTraffic(localEndpoint, remoteEndpoint *v1.EndpointSpec, lc, tx, rx int64, ipFamily k8snet.IPFamily) {
	remoteEndpoint.BackendConfig[lastChecked] = strconv.FormatInt(lc, 10)
	remoteEndpoint.BackendConfig[transmitBytes] = strconv.FormatInt(tx, 10)
	remoteEndpoint.BackendConfig[receiveBytes] = strconv.FormatInt(rx, 10)

	cable.RecordTxBytes(cableDriverName, localEndpoint, remoteEndpoint, int(tx), ipFamily)
	cable.RecordRxBytes(cableDriverName, localEndpoint, remoteEndpoint, int(rx), ipFamily)
}
