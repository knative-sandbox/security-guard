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
	"math/bits"
	"net"
)

//////////////////// IpSetProfile ////////////////

// Exposes ValueProfile interface
type IpSetProfile []net.IP

func (profile *IpSetProfile) profileI(args ...interface{}) {
	switch v := args[0].(type) {
	case string:
		profile.ProfileString(v)
	case net.IP:
		profile.ProfileIP(v)
	case []net.IP:
		profile.ProfileIPSlice(v)
	default:
		panic("Unsupported type in IpSetProfile")
	}
}

func (profile *IpSetProfile) ProfileString(str string) {
	*profile = nil
	if len(str) > 0 {
		if ip := net.ParseIP(str); ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() {
			if ipv4 := ip.To4(); ipv4 != nil {
				ip = ipv4
			}
			*profile = append(*profile, ip)
		}
	}
}

func (profile *IpSetProfile) ProfileIP(ip net.IP) {
	*profile = nil
	if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() {
		*profile = IpSetProfile{ip}
	}
}

func (profile *IpSetProfile) ProfileIPSlice(ipSlice []net.IP) {
	*profile = nil
	for _, ip := range ipSlice {

		if ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() {
			dup := make(net.IP, len(ip))
			copy(dup, ip)
			*profile = append(*profile, dup)
		}
	}
}

//////////////////// IpSetPile ////////////////

// Exposes ValuePile interface
// During json.Marshal(), IpSetPile exposes only the List
// After json.Unmarshal(), the map will be nil even when the List is not empty
// If the map is nil, it should be populated from the information in List
// If the map is populated it is always kept in-sync with the information in List
type IpSetPile struct {
	List []net.IP
	m    map[string]bool
}

func (pile *IpSetPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*IpSetProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *IpSetPile) Add(profile *IpSetProfile) {
	if pile.m == nil {
		pile.m = make(map[string]bool, len(pile.List)+16)
		// Populate the map from the information in List
		for _, v := range pile.List {
			pile.m[v.String()] = true
		}
	}
	for _, v := range *profile {
		ipStr := v.String()
		if !pile.m[ipStr] {
			pile.m[ipStr] = true
			v_copy := make(net.IP, len(v))
			copy(v_copy, v)
			pile.List = append(pile.List, v_copy)
		}
	}
}

func (pile *IpSetPile) Clear() {
	pile.m = nil
	pile.List = nil
}

func (pile *IpSetPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*IpSetPile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *IpSetPile) Merge(otherPile *IpSetPile) {
	if pile.m == nil {
		pile.m = make(map[string]bool, len(pile.List)+len(otherPile.List))
		// Populate the map from the information in List
		for _, v := range pile.List {
			pile.m[v.String()] = true
		}
	}
	for _, v := range otherPile.List {
		ipStr := v.String()
		if !pile.m[ipStr] {
			pile.m[ipStr] = true
			v_copy := make(net.IP, len(v))
			copy(v_copy, v)
			pile.List = append(pile.List, v_copy)
		}
	}
}

//////////////////// CidrSetConfig ////////////////

type CIDR net.IPNet

func (cidr *CIDR) lastIP() net.IP {
	var lastIp net.IP = make(net.IP, len(cidr.IP))
	copy(lastIp, cidr.IP)
	for i, b := range cidr.Mask {
		lastIp[i] |= ^b
	}
	return lastIp
}

// Return true if cidr include the ip range of otherCidr
func (cidr *CIDR) Include(otherCidr CIDR) bool {
	// Check first IP of otherCidr
	if (*net.IPNet)(cidr).Contains(otherCidr.IP) {
		// Check last IP of otherCidr
		return (*net.IPNet)(cidr).Contains(otherCidr.lastIP())
	}
	return false
}

// InflateBy try to add IP to a CIDR by extending the CIDR mask
// The maximal extension allowed by the implementation is a C Subnet
// (i.e. mask of 255.255.255.0 in IPv4)
// InflateBy returns true if successful
func (cidr *CIDR) InflateBy(ip net.IP) bool {
	if (*net.IPNet)(cidr).Contains(ip) {
		return true
	}

	cidrLen := len(cidr.IP)
	if len(ip) != cidrLen {
		// never try to mingle ipv4 and ipv6 staff
		return false
	}

	// lets try to inflate
	cidrLast := cidrLen - 1
	cidrBits := cidrLen * 8
	// Is the Ip in the same C Subnet as the CIDR?
	for i := 0; i < cidrLast; i++ {
		xor := cidr.IP[i] ^ ip[i]
		if xor != 0 {
			// Avoid creating cidrs larger than C Subnets
			return false
		}
	}

	// Inflate the CIDR to cover the IP as well!
	xor := cidr.IP[cidrLast] ^ ip[cidrLast]
	bitsShared := bits.LeadingZeros8(xor)
	mask := net.CIDRMask(cidrBits-8+bitsShared, cidrBits)
	cidr.IP = cidr.IP.Mask(mask)
	cidr.Mask[cidrLast] &= mask[cidrLast]
	return true
}

// Exposes ValueConfig interface
type IpSetConfig []CIDR

func (config *IpSetConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide((valProfile.(*IpSetProfile)))
}

func (config *IpSetConfig) Decide(profile *IpSetProfile) *Decision {
	var current *Decision

	if len(*profile) == 0 {
		return nil
	}

LoopProfileIPs:
	for _, ip := range *profile {
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() {
			continue LoopProfileIPs
		}
		for _, subnet := range *config {
			if (*net.IPNet)(&subnet).Contains(ip) {
				continue LoopProfileIPs
			}
		}
		DecideInner(&current, 1, "IP %s not allowed", ip.String())
	}
	return current
}

// Learn currently offers a rough and simple CIDR support
// Learn try to add IPs to current CIDRs by inflating the CIDRs.
// When no CIDR can be inflated to include the IP, Learn adds a new CIDR for this IP
// Future: Improve Learn to squash consecutive cidrs

func (config *IpSetConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*IpSetPile))
}

// pile is RO and unchanged - never uses pile internal objects
func (config *IpSetConfig) Learn(pile *IpSetPile) {
LoopPileIPs:
	for _, ip := range pile.List {
		for _, cidr := range *config {
			if cidr.InflateBy(ip) {
				continue LoopPileIPs
			}
		}
		// Unsuccessful inflating CIDRs to include IP
		ip_copy := make(net.IP, len(ip))
		copy(ip_copy, ip)
		if len(ip) == 4 {
			*config = append(*config, (CIDR)(net.IPNet{IP: ip_copy, Mask: net.CIDRMask(32, 32)}))
		} else {
			*config = append(*config, (CIDR)(net.IPNet{IP: ip_copy, Mask: net.CIDRMask(128, 128)}))
		}
	}
}

func (config *IpSetConfig) Prepare() {
}
