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
// Future: Improve Learn - e.g. by supporting more then one range
func (config *CountConfig) Learn(pile CountPile) {
	if len(pile) == 0 {
		return
	}

	min := pile[0]
	max := pile[0]
	for _, v := range pile {
		if min > v {
			min = v
		}
		if max < v {
			max = v
		}
	}

	if *config == nil {
		*config = append(*config, countRange{min, max})
		return
	}

	if min < (*config)[0].Min {
		(*config)[0].Min = min
	}
	if max > (*config)[0].Max {
		(*config)[0].Max = max
	}
}

func (config *CountConfig) Prepare() {
}
