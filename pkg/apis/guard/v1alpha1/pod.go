/*
Copyright 2022 The Knative Authors

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

package v1alpha1

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"

	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

var procNet string = "/proc/net/"

// Looking for first location of byte in an array of bytes
func findByte(data []byte, target byte) int {
	for i, b := range data {
		if b == target { // found the byte
			return i
		}
	}
	return -1
}

// Given a byte array from /proc/net/{tcp|udp|udpite|tcp6|udp6|tcplite6} find the next Remote Ip
func nextRemoteIp(data_in []byte) (net.IP, []byte) {
	var i int
	var data []byte = data_in
	var ipstr string
NextLine:
	for {
		ipstr = ""

		// 1. Move forward in data and find next candidate ipstr
		i = findByte(data, 0xA) // find new line
		if i < 0 {
			return nil, nil
		}

		data = data[i+1:]        // moved to new line
		i = findByte(data, 0x3A) // find first colon
		if i < 0 {
			continue NextLine
		}
		data = data[i+1:]        // moved to char after first colon
		i = findByte(data, 0x3A) // find second colon
		if i < 0 {
			continue NextLine
		}
		data = data[i+1:]        // moved to char after second colon
		i = findByte(data, 0x3A) // find third colon
		if i < 13 {
			continue NextLine
		}
		ipstr = string(data[5:i]) // the remove ip
		data = data[i+1:]         // moved to char after third colon

		// 2. Try to process ipstr
		//    We return nil if no more IPs or if ip has bad format

		var ip net.IP
		if len(ipstr) == 8 { //ipv4
			ip = make(net.IP, net.IPv4len)
			v, err := strconv.ParseUint(ipstr, 16, 32)
			if err != nil {
				continue NextLine
			}
			binary.LittleEndian.PutUint32(ip, uint32(v))
		} else if len(ipstr) == 32 { //ipv6
			ip = make(net.IP, net.IPv6len)
			for i := 0; i < 16; i += 4 {
				u, err := strconv.ParseUint(ipstr[0:8], 16, 32)
				if err != nil {
					continue NextLine
				}
				binary.LittleEndian.PutUint32(ip[i:i+4], uint32(u))
				ipstr = ipstr[8:] //skip 8 bytes
			}
		} else {
			// skip
			continue NextLine
		}

		// 3. Success!! If ip of interest  - back to caller, else move to next line

		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() {
			continue NextLine
		}

		return ip, data
	}
}

// Given a protocol {tcp|udp|udpite|tcp6|udp6|tcplite6} get the list of Remote Ips from /proc/net
func IpNetFromProc(protocol string) (ips []net.IP) {
	procfile := procNet + protocol
	data, err := os.ReadFile(procfile)
	if err != nil {
		pi.Log.Infof("error while reading %s: %s\n", procfile, err.Error())
		return
	}

	ips = make([]net.IP, 0)
	ip, data := nextRemoteIp(data)
	for data != nil {
		ips = append(ips, ip)
		ip, data = nextRemoteIp(data)
	}
	return ips
}

//////////////////// PodProfile ////////////////

// Exposes ValueProfile interface
// Support monitoring /proc/net Ips
// Future support for monitoring /proc/<PID>, /proc/<PID>/fd,  /proc/*/cmdline, /proc/<PID>/io while sharing Process Namespace...
type PodProfile struct {
	// from local /proc/net (same net namespace)
	Tcp4Peers     IpSetProfile `json:"tcp4peers"`     // from /proc/net/tcp
	Udp4Peers     IpSetProfile `json:"udp4peers"`     // from /proc/net/udp
	Udplite4Peers IpSetProfile `json:"udplite4peers"` // from /proc/udpline
	Tcp6Peers     IpSetProfile `json:"tcp6peers"`     // from /proc/net/tcp6
	Udp6Peers     IpSetProfile `json:"udp6peers"`     // from /proc/net/udp6
	Udplite6Peers IpSetProfile `json:"udplite6peers"` // from /proc/net/udpline6
}

func (profile *PodProfile) profileI(args ...interface{}) {
	profile.Profile()
}

func (profile *PodProfile) Profile(args ...interface{}) {
	profile.Tcp4Peers.ProfileIPSlice(IpNetFromProc("tcp"))
	profile.Udp4Peers.ProfileIPSlice(IpNetFromProc("udp"))
	profile.Udplite4Peers.ProfileIPSlice(IpNetFromProc("udplite"))
	profile.Tcp6Peers.ProfileIPSlice(IpNetFromProc("tcp6"))
	profile.Udp6Peers.ProfileIPSlice(IpNetFromProc("udp6"))
	profile.Udplite6Peers.ProfileIPSlice(IpNetFromProc("udplite6"))
}

//////////////////// PodPile ////////////////

// Exposes ValuePile interface
type PodPile struct {
	Tcp4Peers     IpSetPile `json:"tcp4peers"`     // from /proc/net/tcp
	Udp4Peers     IpSetPile `json:"udp4peers"`     // from /proc/net/udp
	Udplite4Peers IpSetPile `json:"udplite4peers"` // from /proc/udpline
	Tcp6Peers     IpSetPile `json:"tcp6peers"`     // from /proc/net/tcp6
	Udp6Peers     IpSetPile `json:"udp6peers"`     // from /proc/net/udp6
	Udplite6Peers IpSetPile `json:"udplite6peers"` // from /proc/net/udpline6
}

func (pile *PodPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*PodProfile))
}

func (pile *PodPile) Add(profile *PodProfile) {
	pile.Tcp4Peers.Add(&profile.Tcp4Peers)
	pile.Udp4Peers.Add(&profile.Udp4Peers)
	pile.Udplite4Peers.Add(&profile.Udplite4Peers)
	pile.Tcp6Peers.Add(&profile.Tcp6Peers)
	pile.Udp6Peers.Add(&profile.Udp6Peers)
	pile.Udplite6Peers.Add(&profile.Udplite6Peers)
}

func (pile *PodPile) Clear() {
	pile.Tcp4Peers.Clear()
	pile.Udp4Peers.Clear()
	pile.Udplite4Peers.Clear()
	pile.Tcp6Peers.Clear()
	pile.Udp6Peers.Clear()
	pile.Udplite6Peers.Clear()
}

func (pile *PodPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*PodPile))
}

func (pile *PodPile) Merge(otherPile *PodPile) {
	pile.Tcp4Peers.Merge(&otherPile.Tcp4Peers)
	pile.Udp4Peers.Merge(&otherPile.Udp4Peers)
	pile.Udplite4Peers.Merge(&otherPile.Udplite4Peers)
	pile.Tcp6Peers.Merge(&otherPile.Tcp6Peers)
	pile.Udp6Peers.Merge(&otherPile.Udp6Peers)
	pile.Udplite6Peers.Merge(&otherPile.Udplite6Peers)
}

//////////////////// PodConfig ////////////////

// Exposes ValueConfig interface
type PodConfig struct {
	Tcp4Peers     IpSetConfig `json:"tcp4peers"`     // from /proc/net/tcp
	Udp4Peers     IpSetConfig `json:"udp4peers"`     // from /proc/net/udp
	Udplite4Peers IpSetConfig `json:"udplite4peers"` // from /proc/udpline
	Tcp6Peers     IpSetConfig `json:"tcp6peers"`     // from /proc/net/tcp6
	Udp6Peers     IpSetConfig `json:"udp6peers"`     // from /proc/net/udp6
	Udplite6Peers IpSetConfig `json:"udplite6peers"` // from /proc/net/udpline6
}

func (config *PodConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*PodProfile))
}

func (config *PodConfig) Decide(profile *PodProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Tcp4Peers.Decide(&profile.Tcp4Peers), "Tcp4Peers")
	DecideChild(&current, config.Udp4Peers.Decide(&profile.Udp4Peers), "Udp4Peers")
	DecideChild(&current, config.Udplite4Peers.Decide(&profile.Udplite4Peers), "Udplite4Peers")
	DecideChild(&current, config.Tcp6Peers.Decide(&profile.Tcp6Peers), "Tcp6Peers")
	DecideChild(&current, config.Udp6Peers.Decide(&profile.Udp6Peers), "Udp6Peers")
	DecideChild(&current, config.Udplite6Peers.Decide(&profile.Udplite6Peers), "Udplite6Peers")
	return current
}

func (config *PodConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*PodPile))
}

func (config *PodConfig) Learn(pile *PodPile) {
	config.Tcp4Peers.Learn(&pile.Tcp4Peers)
	config.Udp4Peers.Learn(&pile.Udp4Peers)
	config.Udplite4Peers.Learn(&pile.Udplite4Peers)
	config.Tcp6Peers.Learn(&pile.Tcp6Peers)
	config.Udp6Peers.Learn(&pile.Udp6Peers)
	config.Udplite6Peers.Learn(&pile.Udplite6Peers)
}

func (config *PodConfig) Prepare() {
	config.Tcp4Peers.Prepare()
	config.Udp4Peers.Prepare()
	config.Udplite4Peers.Prepare()
	config.Tcp6Peers.Prepare()
	config.Udp6Peers.Prepare()
	config.Udplite6Peers.Prepare()
}
