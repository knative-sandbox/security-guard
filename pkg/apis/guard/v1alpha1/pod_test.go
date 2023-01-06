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
	"os"
	"testing"
)

func updateAll(data []byte) {
	procNet = "/tmp/proc/net/"
	os.MkdirAll(procNet, os.ModePerm)
	os.WriteFile(procNet+"tcp", data, 0644)
	os.WriteFile(procNet+"udp", data, 0644)
	os.WriteFile(procNet+"udplite", data, 0644)
	os.WriteFile(procNet+"tcp6", data, 0644)
	os.WriteFile(procNet+"udp6", data, 0644)
	os.WriteFile(procNet+"udplite6", data, 0644)
}

func TestPod_V1(t *testing.T) {

	data1 := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 02001102:E12E 0217D902:0050 06 00000000:00000000 03:00001599 00000000     0        0 0 3 0000000000000000
1: 02001102:C6F0 02B9FA02:0050 06 00000000:00000000 03:00001569 00000000     0        0 0 3 0000000000000000`)

	data2 := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 02001104:E12E 0417D902:0050 06 00000000:00000000 03:00001599 00000000     0        0 0 3 0000000000000000
1: 02001104:C6F0 04B9FA02:0050 06 00000000:00000000 03:00001569 00000000     0        0 0 3 0000000000000000`)

	data3 := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 02001103:E12E 0317D902:0050 06 00000000:00000000 03:00001599 00000000     0        0 0 3 0000000000000000
1: 02001103:C6F0 03B9FA02:0050 06 00000000:00000000 03:00001569 00000000     0        0 0 3 0000000000000000`)

	// ipv6 sample
	data4 := []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	0: 00000000000000000000000000000000:006F 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19587 1 ffff880262630000 100 0 0 10 -1
	1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22011 1 ffff880261c887c0 100 0 0 10 -1
	2: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21958 1 ffff880261c88000 100 0 0 10 -1
	3: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 28592 1 ffff88024eea0000 100 0 0 10 -1`)

	t.Run("CIDR management", func(t *testing.T) {
		var profile1 PodProfile
		var profile1a PodProfile
		var profile2 PodProfile
		var profile2a PodProfile
		var profile3 PodProfile
		var profile4 PodProfile
		var profile5 PodProfile
		var profile6 PodProfile
		var pile1 PodPile
		var pile2 PodPile
		var config1 PodConfig
		var config1a PodConfig
		var config2 PodConfig
		var config56 PodConfig

		updateAll(data1)
		profile1.Profile()
		profile1a.Profile()
		updateAll(data2)
		profile2.Profile()
		profile2a.Profile()
		updateAll(data3)
		profile3.Profile()
		profile4.Profile()
		updateAll(data4)
		profile5.Profile()
		profile6.Profile()

		pile1.Add(&profile1)
		config1.Learn(&pile1)
		if d := config1.Decide(&profile1); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}
		if d := config1.Decide(&profile2); d == nil {
			t.Errorf("Decide return ok when expected an error")
		}
		if d := config1.Decide(&profile3); d == nil {
			t.Errorf("Decide return ok when expected an error")
		}
		pile2.Add(&profile2)
		pile2.Merge(&pile1)
		config2.Learn(&pile2)
		if d := config2.Decide(&profile1); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}
		if d := config2.Decide(&profile2); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}
		if d := config2.Decide(&profile3); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}
		if d := config2.Decide(&profile5); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}

		pile1.Clear()
		pile2.Clear()
		pile1.Add(&profile1a)
		pile2.Add(&profile2a)
		config1a.Learn(&pile1)
		config1a.Learn(&pile2)
		if d := config1a.Decide(&profile1); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}
		if d := config1a.Decide(&profile2); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}

		if d := config1a.Decide(&profile3); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}

		pile1.Clear()
		pile2.Clear()
		pile1.Add(&profile3)
		pile2.Add(&profile4)
		config56.Learn(&pile2)
		pile1.Clear()
		pile2.Clear()
		pile1.Add(&profile5)
		pile2.Add(&profile6)
		config56.Learn(&pile2)

		if d := config56.Decide(&profile3); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}

		if d := config56.Decide(&profile5); d != nil {
			t.Errorf(d.String("Decide expected to ok but returned error"))
		}

	})
}
