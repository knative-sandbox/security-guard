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

//////////////////// CountProfile ////////////////

// Exposes ValueProfile interface
type CountProfile uint8

func (profile *CountProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(uint8))
}

func (profile *CountProfile) Profile(val uint8) {
	*profile = CountProfile(val)
}

//////////////////// CountPile ////////////////

// Exposes ValuePile interface
type CountPile []uint8

func (pile *CountPile) addI(valProfile ValueProfile) {
	pile.Add(*valProfile.(*CountProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *CountPile) Add(profile CountProfile) {
	*pile = append(*pile, uint8(profile))
}

func (pile *CountPile) Clear() {
	*pile = nil
}

func (pile *CountPile) mergeI(otherValPile ValuePile) {
	pile.Merge(*otherValPile.(*CountPile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *CountPile) Merge(otherPile CountPile) {
	*pile = append(*pile, otherPile...)
}

// ////////////////// CountConfig ////////////////
type countRange struct {
	Min uint8 `json:"min"`
	Max uint8 `json:"max"`
}

func (cRange *countRange) fuseTwoRanges(otherRange *countRange) bool {
	if cRange.Max < otherRange.Min || cRange.Min > otherRange.Max {
		// no overlap - nothing to do!
		return false
	}

	// There is overlap of some sort
	if cRange.Min > otherRange.Min {
		cRange.Min = otherRange.Min
	}
	if cRange.Max < otherRange.Max {
		cRange.Max = otherRange.Max
	}
	return true
}

// Exposes ValueConfig interface
type CountConfig []countRange

func (config *CountConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(*valProfile.(*CountProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (config *CountConfig) Decide(profile CountProfile) *Decision {
	var current *Decision

	if profile == 0 {
		return nil
	}
	// v>0
	if len(*config) == 0 {
		DecideInner(&current, 1, "Value %d Not Allowed!", profile)
		return current
	}

	for _, cRange := range *config {
		if uint8(profile) < cRange.Min {
			break
		}
		if uint8(profile) <= cRange.Max { // found ok interval
			return nil
		}
	}
	DecideInner(&current, 1, "Counter out of Range: %d", profile)
	return current
}

func (config *CountConfig) learnI(valPile ValuePile) {
	config.Learn(*valPile.(*CountPile))
}

// Learn now offers the simplest single rule support
// pile is RO and unchanged - never uses pile internal objects
// Future: Improve Learn
func (config *CountConfig) Learn(pile CountPile) {
	min := uint8(0)
	max := uint8(0)
	if len(pile) > 0 {
		min = pile[0]
		max = pile[0]
	}
	for _, v := range pile {
		if min > v {
			min = v
		}
		if max < v {
			max = v
		}
	}
	*config = append(*config, countRange{min, max})
}

func (config *CountConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(*otherValConfig.(*CountConfig))
}

// Fuse CountConfig in-place
// otherValConfig is RO and unchanged - never uses otherValConfig internal objects
// The implementation look to opportunistically merge new entries to existing ones
// The implementation does now squash entries even if after the Fuse they may be squashed
// This is done to achieve Fuse in-place
// Future: Improve Fuse - e.g. by keeping extra entries in Range [0,0] and reusing them instead of adding new entries
func (config *CountConfig) Fuse(otherConfig CountConfig) {
	var fused bool
	for _, other := range otherConfig {
		fused = false
		for idx, this := range *config {
			if fused = this.fuseTwoRanges(&other); fused {
				(*config)[idx] = this
				break
			}
		}
		if !fused {
			// Creating new countRange avoids both objects pointing to the same object
			*config = append(*config, countRange{other.Min, other.Max})
		}
	}
}

func (config *CountConfig) Prepare() {
}
