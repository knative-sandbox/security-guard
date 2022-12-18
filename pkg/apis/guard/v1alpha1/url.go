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
	"strings"
)

//////////////////// UrlProfile ////////////////

// Exposes ValueProfile interface
type UrlProfile struct {
	Val      SimpleValProfile `json:"val"`
	Segments CountProfile     `json:"segments"`
}

func (profile *UrlProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(string))
}

func (profile *UrlProfile) Profile(path string) {
	segments := strings.Split(path, "/")
	numSegments := len(segments)
	if (numSegments > 0) && segments[0] == "" {
		segments = segments[1:]
		numSegments--
	}
	if (numSegments > 0) && segments[numSegments-1] == "" {
		numSegments--
		segments = segments[:numSegments]

	}
	cleanPath := strings.Join(segments, "")
	//profile.Val = new(SimpleValProfile)
	profile.Val.Profile(cleanPath)

	if numSegments > 0xFF {
		numSegments = 0xFF
	}
	profile.Segments.Profile(uint8(numSegments))
}

//////////////////// UrlPile ////////////////

// Exposes ValuePile interface
type UrlPile struct {
	Val      SimpleValPile `json:"val"`
	Segments CountPile     `json:"segments"`
}

func (pile *UrlPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*UrlProfile))
}

func (pile *UrlPile) Add(profile *UrlProfile) {
	pile.Segments.Add(profile.Segments)
	pile.Val.Add(&profile.Val)
}

func (pile *UrlPile) Clear() {
	pile.Segments.Clear()
	pile.Val.Clear()
}

func (pile *UrlPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*UrlPile))
}

func (pile *UrlPile) Merge(otherPile *UrlPile) {
	pile.Segments.Merge(otherPile.Segments)
	pile.Val.Merge(&otherPile.Val)
}

//////////////////// UrlConfig ////////////////

// Exposes ValueConfig interface
type UrlConfig struct {
	Val      SimpleValConfig `json:"val"`
	Segments CountConfig     `json:"segments"`
}

func (config *UrlConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*UrlPile))
}

func (config *UrlConfig) Learn(pile *UrlPile) {
	config.Segments.Learn(pile.Segments)
	config.Val.Learn(&pile.Val)
}

func (config *UrlConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*UrlConfig))
}

func (config *UrlConfig) Fuse(otherConfig *UrlConfig) {
	config.Segments.Fuse(otherConfig.Segments)
	config.Val.Fuse(&otherConfig.Val)
}

func (config *UrlConfig) decideI(valProfile ValueProfile) *Decision {

	return config.Decide(valProfile.(*UrlProfile))
}

func (config *UrlConfig) Decide(profile *UrlProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Segments.Decide(profile.Segments), "Segments")
	DecideChild(&current, config.Val.Decide(&profile.Val), "Val")
	return current
}

func (config *UrlConfig) Prepare() {
	config.Segments.Prepare()
	config.Val.Prepare()
}
