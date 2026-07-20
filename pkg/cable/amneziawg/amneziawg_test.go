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

package amneziawg_test

import (
	"context"
	"flag"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	"github.com/submariner-io/admiral/pkg/resource"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cable/amneziawg"
	"github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	netlinkAPI "github.com/submariner-io/submariner/pkg/netlink"
	fakeNetlink "github.com/submariner-io/submariner/pkg/netlink/fake"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/vishvananda/netlink"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
)

func init() {
	kzerolog.AddFlags(nil)
}

var _ = BeforeSuite(func() {
	flags := flag.NewFlagSet("kzerolog", flag.ExitOnError)
	kzerolog.AddFlags(flags)
	_ = flags.Parse([]string{"-v=4"})

	kzerolog.InitK8sLogging()
})

func TestAmneziaWG(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "AmneziaWG Suite")
}

const (
	listenPort  = 123
	listenPort2 = 456
)

var _ = Describe("Driver", func() {
	Context("NewDriver", testNewDriver)
	Context("Init", testInit)
	Context("ConnectToEndpoint", testConnectToEndpoint)
	Context("DisconnectFromEndpoint", testDisconnectFromEndpoint)
	Context("GetConnections", testGetConnections)
	Context("Cleanup", testCleanup)

	Context("", func() {
		t := newTestDriver()

		Specify("GetName should return amneziawg", func() {
			Expect(t.driver.GetName()).To(Equal("amneziawg"))
		})
	})
})

type noopUserspaceDevice struct{}

func (noopUserspaceDevice) Close() error { return nil }

type testDriver struct {
	endpointSpec      submarinerv1.EndpointSpec
	localEndpoint     *endpoint.Local
	driver            cable.Driver
	netLink           *fakeNetlink.NetLink
	client            *fakeClient
	checkNewDriverErr func(error)
}

func newTestDriver() *testDriver {
	t := &testDriver{}

	BeforeEach(func() {
		os.Setenv("CE_IPSEC_PSK", "test-psk-value")
		os.Unsetenv(cable.CableDriverOptionsEnv)

		t.endpointSpec = submarinerv1.EndpointSpec{
			ClusterID:  "local",
			CableName:  "submariner-cable-local-192-68-1-1",
			PrivateIPs: []string{"192.68.1.1"},
			Subnets:    []string{"10.0.0.0/16"},
			BackendConfig: map[string]string{
				submarinerv1.UDPPortConfig: strconv.Itoa(listenPort),
			},
		}

		t.netLink = fakeNetlink.New()
		netlinkAPI.NewFunc = func() netlinkAPI.Interface {
			return t.netLink
		}

		t.client = &fakeClient{}
		t.client.devices = map[string]*wgtypes.Device{}

		amneziawg.NewClient = func() (amneziawg.Client, error) {
			return t.client, nil
		}

		amneziawg.StartUserspaceDeviceForTest = func(ifaceName string) (amneziawg.UserspaceDevice, error) {
			_ = t.netLink.LinkAdd(&netlink.GenericLink{
				LinkAttrs: netlink.LinkAttrs{
					Name: ifaceName,
				},
			})

			return noopUserspaceDevice{}, nil
		}

		t.checkNewDriverErr = func(err error) {
			Expect(err).NotTo(HaveOccurred())
		}
	})

	JustBeforeEach(func() {
		var err error

		t.localEndpoint = endpoint.NewLocal(&t.endpointSpec, dynamicfake.NewSimpleDynamicClient(scheme.Scheme), "")

		t.driver, err = amneziawg.NewDriver(t.localEndpoint, &types.SubmarinerCluster{}, nil)
		t.checkNewDriverErr(err)
	})

	return t
}

func testNewDriver() {
	t := newTestDriver()

	BeforeEach(func() {
		t.client.devices[amneziawg.DefaultDeviceName] = &wgtypes.Device{
			Peers: []wgtypes.Peer{{PublicKey: wgtypes.Key{}}},
		}
	})

	It("should configure the device with obfuscation parameters and public key", func() {
		device := t.client.devices[amneziawg.DefaultDeviceName]
		Expect(device).ToNot(BeNil())
		Expect(device.ListenPort).To(Equal(listenPort))
		Expect(device.PublicKey).ToNot(Equal(wgtypes.Key{}))
		Expect(device.PrivateKey).ToNot(Equal(wgtypes.Key{}))
		Expect(device.Jc).To(Equal(7))
		Expect(device.H1).To(Equal("200000000-280000000"))
		Expect(device.S3).To(Equal(35))
		Expect(device.I1).To(Equal("<r 40>"))
		Expect(device.Peers).To(BeEmpty(), "ReplacePeers should clear the pre-seeded peer")

		Expect(t.localEndpoint.Spec().BackendConfig[amneziawg.PublicKey]).To(Equal(device.PublicKey.String()))
		Expect(t.localEndpoint.Spec().BackendConfig[cable.InterfaceNameConfig]).To(Equal(amneziawg.DefaultDeviceName))
	})

	When("cable driver options are set", func() {
		BeforeEach(func() {
			os.Setenv(cable.CableDriverOptionsEnv, `{"jc":"3","h1":"10-20","i1":"<b 64>"}`)
		})

		AfterEach(func() {
			os.Unsetenv(cable.CableDriverOptionsEnv)
		})

		It("should override the default obfuscation parameters", func() {
			device := t.client.devices[amneziawg.DefaultDeviceName]
			Expect(device.Jc).To(Equal(3))
			Expect(device.H1).To(Equal("10-20"))
			Expect(device.I1).To(Equal("<b 64>"))
			Expect(device.S3).To(Equal(35))
		})
	})
}

func testInit() {
	t := newTestDriver()

	It("should succeed", func() {
		Expect(t.driver.Init(context.TODO())).To(Succeed())
		t.netLink.AwaitLinkSetup(amneziawg.DefaultDeviceName)
	})
}

func testConnectToEndpoint() {
	t := newTestDriver()

	It("should configure a peer for the remote endpoint", func() {
		natInfo := newNATInfo("remote", "172.16.0.0/16")

		_, err := t.driver.ConnectToEndpoint(natInfo)
		Expect(err).ToNot(HaveOccurred())

		t.client.assertDevicePeers(natInfo)
	})
}

func testDisconnectFromEndpoint() {
	t := newTestDriver()

	It("should remove the peer", func() {
		natInfo := newNATInfo("remote", "172.16.0.0/16")
		_, err := t.driver.ConnectToEndpoint(natInfo)
		Expect(err).ToNot(HaveOccurred())

		err = t.driver.DisconnectFromEndpoint(&types.SubmarinerEndpoint{Spec: natInfo.Endpoint.Spec}, k8snet.IPv4)
		Expect(err).ToNot(HaveOccurred())

		device, err := t.client.Device(amneziawg.DefaultDeviceName)
		Expect(err).ToNot(HaveOccurred())
		Expect(device.Peers).To(BeEmpty())
	})
}

func testGetConnections() {
	t := newTestDriver()

	It("should return tracked connections", func() {
		natInfo := newNATInfo("remote", "172.16.0.0/16")
		_, err := t.driver.ConnectToEndpoint(natInfo)
		Expect(err).ToNot(HaveOccurred())

		t.assertConnections(natInfo)
	})
}

func testCleanup() {
	t := newTestDriver()

	It("should delete the device link", func() {
		Expect(t.driver.Cleanup(nil)).To(Succeed())
		t.netLink.AwaitNoLink(amneziawg.DefaultDeviceName)
	})
}

func (t *testDriver) assertConnections(natInfos ...*natdiscovery.NATEndpointInfo) {
	actual, err := t.driver.GetConnections()
	Expect(err).ToNot(HaveOccurred())

	for i := range actual {
		actual[i].StatusMessage = ""
	}

	slices.SortFunc(actual, func(a, b submarinerv1.Connection) int {
		return strings.Compare(a.Endpoint.BackendConfig[amneziawg.PublicKey], b.Endpoint.BackendConfig[amneziawg.PublicKey])
	})

	expected := make([]submarinerv1.Connection, len(natInfos))
	for i := range natInfos {
		expected[i] = submarinerv1.Connection{
			Status:   submarinerv1.Connecting,
			Endpoint: natInfos[i].Endpoint.Spec,
			UsingIP:  natInfos[i].UseIP,
			UsingNAT: natInfos[i].UseNAT,
		}
	}

	slices.SortFunc(expected, func(a, b submarinerv1.Connection) int {
		return strings.Compare(a.Endpoint.BackendConfig[amneziawg.PublicKey], b.Endpoint.BackendConfig[amneziawg.PublicKey])
	})

	Expect(actual).To(HaveExactElements(expected))
}

func newNATInfo(clusterID string, subnets ...string) *natdiscovery.NATEndpointInfo {
	priv, err := wgtypes.GeneratePrivateKey()
	Expect(err).ToNot(HaveOccurred())

	return &natdiscovery.NATEndpointInfo{
		Endpoint: submarinerv1.Endpoint{
			Spec: submarinerv1.EndpointSpec{
				ClusterID: clusterID,
				CableName: "submariner-cable-" + clusterID,
				Subnets:   subnets,
				BackendConfig: map[string]string{
					amneziawg.PublicKey:        priv.PublicKey().String(),
					submarinerv1.UDPPortConfig: strconv.Itoa(listenPort2),
				},
			},
		},
		UseIP:     "172.93.2.1",
		UseNAT:    true,
		UseFamily: k8snet.IPv4,
	}
}

type fakeClient struct {
	devices            map[string]*wgtypes.Device
	configureDeviceErr error
}

func (c *fakeClient) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if c.configureDeviceErr != nil {
		return c.configureDeviceErr
	}

	d := c.devices[name]
	if d == nil {
		c.devices[name] = &wgtypes.Device{}
		d = c.devices[name]
	}

	if cfg.PrivateKey != nil {
		d.PrivateKey = *cfg.PrivateKey
		d.PublicKey = d.PrivateKey.PublicKey()
	}

	if cfg.ListenPort != nil {
		d.ListenPort = *cfg.ListenPort
	}

	if cfg.Jc != nil {
		d.Jc = *cfg.Jc
	}

	if cfg.S3 != nil {
		d.S3 = *cfg.S3
	}

	if cfg.H1 != nil {
		d.H1 = *cfg.H1
	}

	if cfg.I1 != nil {
		d.I1 = *cfg.I1
	}

	if cfg.ReplacePeers {
		d.Peers = nil
	}

	for i := range cfg.Peers {
		pc := &cfg.Peers[i]
		if pc.Remove {
			d.Peers = slices.DeleteFunc(d.Peers, func(p wgtypes.Peer) bool {
				return p.PublicKey.String() == pc.PublicKey.String()
			})

			continue
		}

		index := slices.IndexFunc(d.Peers, func(p wgtypes.Peer) bool {
			return p.PublicKey.String() == pc.PublicKey.String()
		})

		if index == -1 {
			if pc.UpdateOnly {
				continue
			}

			d.Peers = append(d.Peers, wgtypes.Peer{
				PublicKey:    pc.PublicKey,
				PresharedKey: ptr.Deref(pc.PresharedKey, wgtypes.Key{}),
				Endpoint:     pc.Endpoint,
			})

			index = len(d.Peers) - 1
		}

		peer := &d.Peers[index]

		if pc.ReplaceAllowedIPs {
			peer.AllowedIPs = pc.AllowedIPs
		} else {
			peer.AllowedIPs = append(peer.AllowedIPs, pc.AllowedIPs...)
		}
	}

	return nil
}

func (c *fakeClient) Device(name string) (*wgtypes.Device, error) {
	if c.devices[name] != nil {
		d := *c.devices[name]
		d.Peers = make([]wgtypes.Peer, len(c.devices[name].Peers))
		copy(d.Peers, c.devices[name].Peers)

		return &d, nil
	}

	return nil, os.ErrNotExist
}

func (c *fakeClient) Close() error {
	return nil
}

func (c *fakeClient) assertDevicePeers(natInfos ...*natdiscovery.NATEndpointInfo) {
	device, err := c.Device(amneziawg.DefaultDeviceName)
	Expect(err).ToNot(HaveOccurred())

	for i := range natInfos {
		index := slices.IndexFunc(device.Peers, func(p wgtypes.Peer) bool {
			return p.PublicKey.String() == natInfos[i].Endpoint.Spec.BackendConfig[amneziawg.PublicKey]
		})
		Expect(index).To(BeNumerically(">=", 0), "Missing expected device peer for %s", resource.ToJSON(natInfos[i]))

		peer := &device.Peers[index]
		Expect(peer.PublicKey.String()).To(Equal(natInfos[i].Endpoint.Spec.BackendConfig[amneziawg.PublicKey]))
		Expect(peer.PresharedKey).ToNot(Equal(wgtypes.Key{}))
		Expect(peer.Endpoint).To(Equal(&net.UDPAddr{
			IP:   net.ParseIP(natInfos[i].UseIP),
			Port: listenPort2,
		}))

		actualIPs := make([]string, len(peer.AllowedIPs))
		for j := range peer.AllowedIPs {
			actualIPs[j] = peer.AllowedIPs[j].String()
		}

		slices.Sort(actualIPs)
		slices.Sort(natInfos[i].Endpoint.Spec.Subnets)
		Expect(actualIPs).To(HaveExactElements(natInfos[i].Endpoint.Spec.Subnets))

		device.Peers = slices.Delete(device.Peers, index, index+1)
	}

	Expect(device.Peers).To(BeEmpty(), "Received unexpected device peers")
}
