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

//////////////////// RespProfile ////////////////
// Does not monitor Trailers

// Exposes ValueProfile interface
type RespProfile struct {
	Headers       HeadersProfile   `json:"headers"`
	MediaType     MediaTypeProfile `json:"mediatype"`     // "text/html"
	ContentLength CountProfile     `json:"contentlength"` // 0
}

func (profile *RespProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(*http.Response))
}

func (profile *RespProfile) Profile(resp *http.Response) {
	profile.Headers.Profile(resp.Header)

	profile.MediaType.Profile(resp.Header.Get("Content-Type"))

	length := resp.ContentLength
	if length > 0 {
		var log2length uint8

		for length > 0 {
			log2length++
			length >>= 1
		}
		profile.ContentLength = CountProfile(log2length)
	}
}

//////////////////// RespPile ////////////////

// Exposes ValuePile interface
type RespPile struct {
	Headers       HeadersPile   `json:"headers"`
	MediaType     MediaTypePile `json:"mediatype"`
	ContentLength CountPile     `json:"contentlength"`
}

func (pile *RespPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*RespProfile))
}

func (pile *RespPile) Add(profile *RespProfile) {
	pile.Headers.Add(&profile.Headers)
	pile.MediaType.Add(&profile.MediaType)
	pile.ContentLength.Add(profile.ContentLength)
}

func (pile *RespPile) Clear() {
	pile.Headers.Clear()
	pile.MediaType.Clear()
	pile.ContentLength.Clear()
}

func (pile *RespPile) mergeI(otherValProfile ValuePile) {
	pile.Merge(otherValProfile.(*RespPile))
}

func (pile *RespPile) Merge(otherPile *RespPile) {
	pile.Headers.Merge(&otherPile.Headers)
	pile.MediaType.Merge(&otherPile.MediaType)
	pile.ContentLength.Merge(otherPile.ContentLength)
}

//////////////////// RespConfig ////////////////

// Exposes ValueConfig interface
type RespConfig struct {
	Headers       HeadersConfig   `json:"headers"`
	MediaType     MediaTypeConfig `json:"mediatype"`
	ContentLength CountConfig     `json:"contentlength"`
}

func (config *RespConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*RespProfile))
}

func (config *RespConfig) Decide(profile *RespProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Headers.Decide(&profile.Headers), "Headers")
	DecideChild(&current, config.MediaType.Decide(&profile.MediaType), "MediaType")
	DecideChild(&current, config.ContentLength.Decide(profile.ContentLength), "ContentLength")
	return current
}

func (config *RespConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*RespPile))
}

func (config *RespConfig) Learn(pile *RespPile) {
	config.Headers.Learn(&pile.Headers)
	config.MediaType.Learn(&pile.MediaType)
	config.ContentLength.Learn(pile.ContentLength)
}

func (config *RespConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*RespConfig))
}

func (config *RespConfig) Fuse(otherConfig *RespConfig) {
	config.Headers.Fuse(&otherConfig.Headers)
	config.MediaType.Fuse(&otherConfig.MediaType)
	config.ContentLength.Fuse(otherConfig.ContentLength)
}

func (config *RespConfig) Prepare() {
	config.Headers.Prepare()
	config.MediaType.Prepare()
	config.ContentLength.Prepare()
}
