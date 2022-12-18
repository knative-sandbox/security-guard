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
	"net/http"
)

//////////////////// HeadersProfile ////////////////

// Exposes ValueProfile interface
type HeadersProfile struct {
	Kv KeyValProfile `json:"kv"`
}

func (profile *HeadersProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(http.Header))
}

func (profile *HeadersProfile) Profile(headers http.Header) {
	profile.Kv.ProfileMapStringSlice(headers)
}

//////////////////// HeadersPile ////////////////

// Exposes ValuePile interface
type HeadersPile struct {
	Kv *KeyValPile `json:"kv"`
}

func (pile *HeadersPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*HeadersProfile))
}

func (pile *HeadersPile) Add(profile *HeadersProfile) {
	if pile.Kv == nil {
		pile.Kv = new(KeyValPile)
	}
	pile.Kv.Add(&profile.Kv)
}

func (pile *HeadersPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*HeadersPile))
}

func (pile *HeadersPile) Merge(otherPile *HeadersPile) {
	if pile.Kv == nil {
		pile.Kv = new(KeyValPile)
	}
	pile.Kv.Merge(otherPile.Kv)
}

func (pile *HeadersPile) Clear() {
	pile.Kv = nil
}

//////////////////// HeadersConfig ////////////////

// Exposes ValueConfig interface
type HeadersConfig struct {
	Kv KeyValConfig `json:"kv"`
}

func (config *HeadersConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*HeadersProfile))
}

func (config *HeadersConfig) Decide(profile *HeadersProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Kv.Decide(&profile.Kv), "KeyVal")
	return current
}

func (config *HeadersConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*HeadersPile))
}

func (config *HeadersConfig) Learn(pile *HeadersPile) {
	config.Kv.Learn(pile.Kv)
}

func (config *HeadersConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*HeadersConfig))
}

func (config *HeadersConfig) Fuse(otherConfig *HeadersConfig) {
	config.Kv.Fuse(&otherConfig.Kv)
}

func (config *HeadersConfig) Prepare() {
	config.Kv.Prepare()
}
