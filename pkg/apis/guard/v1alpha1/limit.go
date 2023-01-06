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

//////////////////// LimitProfile ////////////////

// Exposes ValueProfile interface
type LimitProfile uint8

func (profile *LimitProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(uint))
}

// Exponentially represent uint up to ~1M using a uint8
// For inputs > ~1M use 255
// Exponential representation help stabilize the limits and avoid unnecessary alerts
// For example 10 means 10, 20 means 24-25, 40 means 80-83 and 50 means 128-135, 80 means 496-527, etc.
func (profile *LimitProfile) Profile(val uint) {
	v := val
	base := uint(0)

	// batch 16, then 32, then 64, etc.
	for v >= 16 {
		base = base + 16
		v -= 16
		v = v >> 1
	}

	res := v + base
	if res > 255 {
		res = 255
	}
	*profile = LimitProfile(res)
}

//////////////////// LimitPile ////////////////

// Exposes ValuePile interface
type LimitPile []uint8

func (pile *LimitPile) addI(valProfile ValueProfile) {
	pile.Add(*valProfile.(*LimitProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *LimitPile) Add(profile LimitProfile) {
	*pile = append(*pile, uint8(profile))
}

func (pile *LimitPile) Clear() {
	*pile = nil
}

func (pile *LimitPile) mergeI(otherValPile ValuePile) {
	pile.Merge(*otherValPile.(*LimitPile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *LimitPile) Merge(otherPile LimitPile) {
	*pile = append(*pile, otherPile...)
}

// ////////////////// LimitConfig ////////////////

// Exposes ValueConfig interface
type LimitConfig uint8

func (config *LimitConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(*valProfile.(*LimitProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (config *LimitConfig) Decide(profile LimitProfile) *Decision {
	var current *Decision

	if uint8(profile) <= uint8(*config) { // found ok interval
		return nil
	}
	DecideInner(&current, 1, "Limit out of Range: %d", profile)
	return current
}

func (config *LimitConfig) learnI(valPile ValuePile) {
	config.Learn(*valPile.(*LimitPile))
}

// Learn now offers the simplest single rule support
func (config *LimitConfig) Learn(pile LimitPile) {
	if len(pile) == 0 {
		return
	}

	max := pile[0]
	for _, v := range pile {

		if max < v {
			max = v
		}
	}

	if max > uint8(*config) {
		(*config) = LimitConfig(max)
	}
}

func (config *LimitConfig) Prepare() {
}
