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
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/certificate"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/resource"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	netlinkAPI "github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/vishvananda/netlink"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// DefaultDeviceName specifies name of the AmneziaWG network device.
	DefaultDeviceName = "submariner"

	// PublicKey is name (key) of publicKey entry in back-end map.
	PublicKey = "publicKey"

	cableDriverName = "amneziawg"
	receiveBytes    = "ReceiveBytes"  // for peer connection status
	transmitBytes   = "TransmitBytes" // for peer connection status
	lastChecked     = "LastChecked"   // for connection peer status
)

var (
	// KeepAliveInterval to use for wg peers.
	KeepAliveInterval = 10 * time.Second

	// HandshakeTimeout is maximal time from handshake a connections is still considered connected.
	HandshakeTimeout = 2*time.Minute + 10*time.Second
)

var logger = log.Logger{Logger: logf.Log.WithName("amneziawg")}

func init() {
	cable.AddDriver(cableDriverName, NewDriver)
}

type specification struct {
	PSK      string `default:"default psk"`
	NATTPort int32  `default:"4500"`
}

type amneziawgDriver struct {
	localEndpoint   v1.EndpointSpec
	connections     map[string]*v1.Connection // clusterID -> remote ep connection
	client          Client
	netLink         netlinkAPI.Interface
	link            netlink.Link
	spec            *specification
	psk             *wgtypes.Key
	userspaceDevice userspaceDevice
}

// NewDriver creates a new AmneziaWG cable driver.
func NewDriver(localEndpoint *endpoint.Local, _ *types.SubmarinerCluster, _ certificate.SigningRequestor) (cable.Driver, error) {
	// We'll panic if localEndpoint is nil, this is intentional
	var err error

	w := amneziawgDriver{
		connections: make(map[string]*v1.Connection),
		spec:        new(specification),
		netLink:     netlinkAPI.New(),
	}

	if err = envconfig.Process(cable.IPSecEnvPrefix, w.spec); err != nil {
		return nil, errors.Wrap(err, "error processing environment config for amneziawg")
	}

	if w.spec.PSK == "" || w.spec.PSK == "default psk" {
		return nil, errors.New("CE_IPSEC_PSK must be set to a strong random value for the AmneziaWG driver")
	}

	if err = w.setupDevice(); err != nil {
		return nil, errors.Wrap(err, "failed to setup AmneziaWG device")
	}

	defer func() {
		if err == nil {
			return
		}

		if w.client != nil {
			if e := w.client.Close(); e != nil {
				logger.Errorf(e, "Failed to close client")
			}

			w.client = nil
		}

		w.cleanupDevice() //nolint:errcheck // Best-effort cleanup on NewDriver failure
	}()

	if w.client, err = NewClient(); err != nil {
		return nil, errors.Wrap(err, "failed to open awgctrl client")
	}

	var priv, pub, psk wgtypes.Key

	if psk, err = genPsk(w.spec.PSK); err != nil {
		return nil, errors.Wrap(err, "error generating pre-shared key")
	}

	w.psk = &psk

	if priv, err = wgtypes.GeneratePrivateKey(); err != nil {
		return nil, errors.Wrap(err, "error generating private key")
	}

	port, err := localEndpoint.Spec().GetBackendPort(v1.UDPPortConfig, w.spec.NATTPort)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %q from local endpoint", v1.UDPPortConfig)
	}

	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ListenPort:   new(int(port)),
		FirewallMark: nil,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{},
	}
	applyCableDriverObfuscation(&cfg)

	if err = w.client.ConfigureDevice(DefaultDeviceName, cfg); err != nil {
		return nil, errors.Wrap(err, "failed to configure AmneziaWG device")
	}

	pub = priv.PublicKey()

	err = localEndpoint.Update(context.TODO(), func(existing *v1.EndpointSpec) {
		existing.BackendConfig[PublicKey] = pub.String()
		existing.BackendConfig[cable.InterfaceNameConfig] = DefaultDeviceName
	})
	if err != nil {
		return nil, errors.Wrap(err, "error updating local endpoint")
	}

	w.localEndpoint = *localEndpoint.Spec()

	logger.V(log.DEBUG).Infof("Created AmneziaWG %s with publicKey %s", DefaultDeviceName, pub)

	return &w, nil
}

func (w *amneziawgDriver) Init(_ context.Context) error {
	logger.V(log.DEBUG).Infof("Initializing AmneziaWG device for cluster %s", w.localEndpoint.ClusterID)

	l, err := w.netLink.InterfaceByName(DefaultDeviceName)
	if err != nil {
		return errors.Wrapf(err, "cannot get AmneziaWG link by name %s", DefaultDeviceName)
	}

	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return errors.Wrap(err, "awgctrl cannot find AmneziaWG device")
	}

	k, _ := keyFromSpec(&w.localEndpoint)
	if k.String() != d.PublicKey.String() {
		return fmt.Errorf("endpoint public key %s is different from device key %s", k, d.PublicKey)
	}

	if err := w.netLink.LinkSetUp(w.link); err != nil {
		return errors.Wrap(err, "failed to bring up AmneziaWG device")
	}

	logger.V(log.DEBUG).Infof("AmneziaWG device %s is up on i/f number %d, listening on port :%d, with key %s",
		w.link.Attrs().Name, l.Index(), d.ListenPort, d.PublicKey)

	return nil
}

func (w *amneziawgDriver) GetName() string {
	return cableDriverName
}

func (w *amneziawgDriver) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	// We'll panic if endpointInfo is nil, this is intentional
	remoteEndpoint := &endpointInfo.Endpoint
	ip := endpointInfo.UseIP

	remoteIP := net.ParseIP(ip)
	if remoteIP == nil {
		return "", fmt.Errorf("failed to parse remote IP %s", ip)
	}

	allowedIPs := remoteEndpoint.Spec.ParseSubnets(endpointInfo.UseFamily)

	remoteKey, err := keyFromSpec(&remoteEndpoint.Spec)
	if err != nil {
		return "", errors.Wrapf(err, "failed to obtain public key for endpoint %s", resource.ToJSON(remoteEndpoint.Spec))
	}

	logger.V(log.DEBUG).Infof("Connecting cluster %q endpoint %q with publicKey %q",
		remoteEndpoint.Spec.ClusterID, remoteIP, remoteKey)

	oldCon, found := w.connections[remoteEndpoint.Spec.ClusterID]
	if found {
		if oldKey, err := keyFromSpec(&oldCon.Endpoint); err == nil {
			if oldKey.String() == remoteKey.String() {
				w.updatePeerStatus(oldCon, oldKey)
				logger.V(log.DEBUG).Infof("Skipping connect for existing peer key %q", oldKey)

				return ip, nil
			}

			if err := w.removePeer(oldKey); err != nil {
				logger.Warningf("Failed to remove old peer %q for cluster %q: %v",
					oldKey, remoteEndpoint.Spec.ClusterID, err)
			}
		}

		delete(w.connections, remoteEndpoint.Spec.ClusterID)
	}

	connection := v1.NewConnection(&remoteEndpoint.Spec, ip, endpointInfo.UseNAT)
	connection.SetStatus(v1.Connecting, "Connection has been created but not yet started")
	w.connections[remoteEndpoint.Spec.ClusterID] = connection

	logger.V(log.DEBUG).Infof("Added connection for cluster %q: %s", remoteEndpoint.Spec.ClusterID,
		resource.ToJSON(connection))

	port, err := remoteEndpoint.Spec.GetBackendPort(v1.UDPPortConfig, w.spec.NATTPort)
	if err != nil {
		logger.Warningf("Error parsing %q from remote endpoint %q - using port %d instead: %v", v1.UDPPortConfig,
			remoteEndpoint.Spec.CableName, w.spec.NATTPort, err)
	}

	remotePort := int(port)

	peerCfg := []wgtypes.PeerConfig{{
		PublicKey:    *remoteKey,
		Remove:       false,
		UpdateOnly:   false,
		PresharedKey: w.psk,
		Endpoint: &net.UDPAddr{
			IP:   remoteIP,
			Port: remotePort,
		},
		PersistentKeepaliveInterval: new(KeepAliveInterval),
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  allowedIPs,
	}}

	err = w.client.ConfigureDevice(DefaultDeviceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peerCfg,
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to configure peer")
	}

	err = w.verifyNewPeer(&peerCfg[0])
	if err != nil {
		if remErr := w.removePeer(remoteKey); remErr != nil {
			logger.Warningf("Failed to remove unverified peer %q: %v", remoteKey, remErr)
		}

		delete(w.connections, remoteEndpoint.Spec.ClusterID)

		return "", errors.Wrap(err, "failed to verify peer configuration")
	}

	logger.V(log.DEBUG).Infof("Successfully connected endpoint peer %q with IP %q", *remoteKey, remoteIP)

	cable.RecordConnection(cableDriverName, &w.localEndpoint, &connection.Endpoint, string(v1.Connected), true, endpointInfo.UseFamily)

	return ip, nil
}

func keyFromSpec(ep *v1.EndpointSpec) (*wgtypes.Key, error) {
	s, found := ep.BackendConfig[PublicKey]
	if !found {
		return &wgtypes.Key{}, errors.New("endpoint is missing public key")
	}

	key, err := wgtypes.ParseKey(s)

	return &key, errors.Wrapf(err, "failed to parse public key %s", s)
}

func (w *amneziawgDriver) DisconnectFromEndpoint(remoteEndpoint *types.SubmarinerEndpoint, family k8snet.IPFamily) error {
	// We'll panic if remoteEndpoint is nil, this is intentional
	logger.V(log.DEBUG).Infof("Removing IPv%v endpoint %s", family, resource.ToJSON(remoteEndpoint))

	remoteKey, err := keyFromSpec(&remoteEndpoint.Spec)
	if err != nil {
		return errors.Wrap(err, "failed to parse peer public key")
	}

	if err := w.removePeer(remoteKey); err != nil {
		logger.Warningf("Failed to remove peer %q for cluster %q: %v",
			remoteKey, remoteEndpoint.Spec.ClusterID, err)
	}

	if w.keyMismatch(remoteEndpoint.Spec.ClusterID, remoteKey) {
		logger.Warningf("Key mismatch for peer cluster %s, keeping existing spec", remoteEndpoint.Spec.ClusterID)
		return nil
	}

	delete(w.connections, remoteEndpoint.Spec.ClusterID)

	logger.V(log.DEBUG).Infof("Done removing endpoint for cluster %q", remoteEndpoint.Spec.ClusterID)
	cable.RecordDisconnected(cableDriverName, &w.localEndpoint, &remoteEndpoint.Spec, family)

	return nil
}

func (w *amneziawgDriver) GetActiveConnections() ([]v1.Connection, error) {
	return make([]v1.Connection, 0), nil
}

func (w *amneziawgDriver) setupDevice() error {
	link, err := w.netLink.LinkByName(DefaultDeviceName)
	switch {
	case err == nil:
		if err := w.netLink.LinkDel(link); err != nil {
			return errors.Wrap(err, "failed to delete existing AmneziaWG device")
		}
	case !netlinkAPI.IsLinkNotFoundError(err):
		return errors.Wrapf(err, "error checking for existing AmneziaWG device %q", DefaultDeviceName)
	}

	var userspaceDev userspaceDevice

	if StartUserspaceDeviceForTest != nil {
		userspaceDev, err = StartUserspaceDeviceForTest(DefaultDeviceName)
	} else {
		userspaceDev, err = startUserspaceDevice(DefaultDeviceName)
	}
	if err != nil {
		return err
	}

	w.userspaceDevice = userspaceDev

	link, err = w.netLink.LinkByName(DefaultDeviceName)
	if err != nil {
		return errors.Wrapf(err, "failed to find AmneziaWG link %s", DefaultDeviceName)
	}

	w.link = link

	return nil
}

func (w *amneziawgDriver) removePeer(key *wgtypes.Key) error {
	logger.V(log.DEBUG).Infof("Removing AmneziaWG peer with key %s", key)

	peerCfg := []wgtypes.PeerConfig{
		{
			PublicKey: *key,
			Remove:    true,
		},
	}

	err := w.client.ConfigureDevice(DefaultDeviceName, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peerCfg,
	})

	return errors.Wrapf(err, "failed to remove AmneziaWG peer with key %s", key)
}

func (w *amneziawgDriver) peerByKey(key *wgtypes.Key) (*wgtypes.Peer, error) {
	d, err := w.client.Device(DefaultDeviceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to find device %s", DefaultDeviceName)
	}

	for i := range d.Peers {
		if d.Peers[i].PublicKey.String() == key.String() {
			return &d.Peers[i], nil
		}
	}

	return nil, fmt.Errorf("peer not found for key %s", key)
}

func (w *amneziawgDriver) verifyNewPeer(peerCfg *wgtypes.PeerConfig) error {
	p, err := w.peerByKey(&peerCfg.PublicKey)
	if err != nil {
		return err
	}

	if p.PresharedKey.String() != peerCfg.PresharedKey.String() {
		return errors.New("peer PresharedKey does not match configured value")
	}

	if p.Endpoint.String() != peerCfg.Endpoint.String() {
		return fmt.Errorf("peer's Endpoint %q does not match configured %q", p.Endpoint.String(), peerCfg.Endpoint.String())
	}

	if !slices.EqualFunc(p.AllowedIPs, peerCfg.AllowedIPs, func(ipn1 net.IPNet, ipn2 net.IPNet) bool {
		return ipn1.String() == ipn2.String()
	}) {
		return fmt.Errorf("peer's AllowedIPs %v does not match configured %q", p.AllowedIPs, peerCfg.AllowedIPs)
	}

	logger.V(log.DEBUG).Infof("Peer configured, PublicKey: %s, EndPoint: %s, AllowedIPs: %v", p.PublicKey, p.Endpoint, p.AllowedIPs)

	return nil
}

func (w *amneziawgDriver) keyMismatch(cid string, key *wgtypes.Key) bool {
	c, found := w.connections[cid]
	if !found {
		logger.Warningf("Could not find spec for cluster %s, mismatched endpoint key %s", cid, key)
		return true
	}

	oldKey, _ := keyFromSpec(&c.Endpoint)
	if oldKey.String() != key.String() {
		logger.Warningf("Key mismatch, cluster %s key is %s, endpoint key is %s", cid, oldKey, key)
		return true
	}

	return false
}

func genPsk(psk string) (wgtypes.Key, error) {
	pskBytes := sha256.Sum256([]byte(psk))
	return wgtypes.NewKey(pskBytes[:]) //nolint:wrapcheck // Let the caller wrap it
}

func (w *amneziawgDriver) Cleanup(_ context.Context) error {
	logger.Info("Uninstalling the amneziawg cable driver")

	return w.cleanupDevice()
}

func (w *amneziawgDriver) cleanupDevice() error {
	if w.userspaceDevice != nil {
		if err := w.userspaceDevice.Close(); err != nil {
			logger.Warningf("Error closing userspace AmneziaWG device: %v", err)
		}

		w.userspaceDevice = nil
	}

	link, err := w.netLink.LinkByName(DefaultDeviceName)
	if netlinkAPI.IsLinkNotFoundError(err) {
		return nil
	}

	if err != nil {
		return errors.Wrapf(err, "error retrieving the AmneziaWG interface %q", DefaultDeviceName)
	}

	err = w.netLink.LinkDel(link)

	return errors.Wrapf(err, "failed to delete existing AmneziaWG device %q", DefaultDeviceName)
}
