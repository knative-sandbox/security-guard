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

//////////////////// FlagSliceProfile ////////////////

// extra is RO and no internal objects are used
func mergeFlagSlices(base []uint32, extra []uint32) []uint32 {
	if missing := len(extra) - len(base); missing > 0 {
		// Dynamically allocate as many blockElements as needed
		base = append(base, make([]uint32, missing)...)
	}

	for i, v := range extra {
		base[i] = base[i] | v
	}
	return base
}

// Exposes ValueProfile interface
type FlagSliceProfile []uint32

func (profile *FlagSliceProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].([]uint32))
}

func (profile *FlagSliceProfile) Profile(vals []uint32) {
	if len(vals) > 0 {
		*profile = vals
	}
}

//////////////////// FlagSlicePile ////////////////

// Exposes ValuePile interface
type FlagSlicePile []uint32

func (pile *FlagSlicePile) addI(valProfile ValueProfile) {
	pile.Add(*valProfile.(*FlagSliceProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *FlagSlicePile) Add(profile FlagSliceProfile) {
	*pile = mergeFlagSlices(*pile, profile)
}

func (pile *FlagSlicePile) Clear() {
	*pile = nil
}

func (pile *FlagSlicePile) mergeI(otherValPile ValuePile) {
	pile.Merge(*otherValPile.(*FlagSlicePile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *FlagSlicePile) Merge(otherPile FlagSlicePile) {
	*pile = mergeFlagSlices(*pile, otherPile)
}

//////////////////// FlagSliceConfig ////////////////

// Exposes ValueConfig interface
type FlagSliceConfig []uint32

func (config *FlagSliceConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(*valProfile.(*FlagSliceProfile))
}

func (config *FlagSliceConfig) Decide(profile FlagSliceProfile) *Decision {
	var current *Decision

	for i, v := range profile {
		if v == 0 {
			continue
		}
		if i < len(*config) && (v & ^(*config)[i]) == 0 {
			continue
		}
		DecideInner(&current, 1, "Unexpected Flags in FlagSlice %x on Element %d", v, i)
	}
	return current
}

func (config *FlagSliceConfig) learnI(valPile ValuePile) {
	config.Learn(*valPile.(*FlagSlicePile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (config *FlagSliceConfig) Learn(pile FlagSlicePile) {
	*config = make(FlagSliceConfig, len(pile))
	copy(*config, pile)
}

func (config *FlagSliceConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(*otherValConfig.(*FlagSliceConfig))
}

// otherConfig is RO and unchanged - never uses otherConfig internal objects
func (config *FlagSliceConfig) Fuse(otherConfig FlagSliceConfig) {
	*config = mergeFlagSlices(*config, otherConfig)
}

func (config *FlagSliceConfig) Prepare() {
}
