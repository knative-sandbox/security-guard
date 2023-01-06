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

type Ctrl struct {
	Alert bool `json:"alert"` // If true, use SessionDataConfig to identify alerts
	Block bool `json:"block"` // If true, block on alert.
	Learn bool `json:"learn"` // If true, and no alert identified, report piles
	Force bool `json:"force"` // If true, learning is done even when alert identified, report piles
	Auto  bool `json:"auto"`  // If true, use learned SessionDataConfig rather than configured SessionDataConfig
}

type GuardianSpec struct {
	Configured *SessionDataConfig `json:"configured"`        // configrued criteria
	Learned    *SessionDataConfig `json:"learned,omitempty"` // Learned citeria
	NumSamples uint32             `json:"samples"`           // Number of Samples Learned
	Control    *Ctrl              `json:"control"`           // Control
}

// AutoActivate is a Guardian operation mode that is useful for security automation of new services
func (g *GuardianSpec) SetToMaximalAutomation() {
	if g.Control == nil {
		g.Control = new(Ctrl)
	}
	g.Control.Auto = true
	g.Control.Learn = true
	g.Control.Force = true
	g.Control.Alert = true
}
