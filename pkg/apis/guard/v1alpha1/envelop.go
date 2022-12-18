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
	"time"
)

// Envelop dataType maintains session data that is collected beyond Req, ReqBody, Resp and RespBody

//////////////////// EnvelopProfile ////////////////

// Exposes ValueProfile interface
type EnvelopProfile struct {
	ResponseTime   CountProfile `json:"responsetime"`
	CompletionTime CountProfile `json:"completiontime"`
}

func (profile *EnvelopProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(time.Time), args[1].(time.Time), args[2].(time.Time))
}

func (profile *EnvelopProfile) Profile(reqTime time.Time, respTime time.Time, endTime time.Time) {

	completionTime := endTime.Sub(reqTime).Seconds()
	if completionTime > 255 {
		profile.CompletionTime = 255
	} else {
		profile.CompletionTime = CountProfile(completionTime)
	}

	responseTime := respTime.Sub(reqTime).Seconds()
	if responseTime > 255 {
		profile.ResponseTime = 255
	} else {
		profile.ResponseTime = CountProfile(responseTime)
	}
}

//////////////////// EnvelopPile ////////////////

// Exposes ValuePile interface
type EnvelopPile struct {
	ResponseTime   CountPile `json:"responsetime"`
	CompletionTime CountPile `json:"completiontime"`
}

func (pile *EnvelopPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*EnvelopProfile))
}

func (pile *EnvelopPile) Add(profile *EnvelopProfile) {
	pile.CompletionTime.Add(profile.CompletionTime)
	pile.ResponseTime.Add(profile.ResponseTime)
}

func (pile *EnvelopPile) Clear() {
	pile.CompletionTime.Clear()
	pile.ResponseTime.Clear()
}

func (pile *EnvelopPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*EnvelopPile))
}

func (pile *EnvelopPile) Merge(otherPile *EnvelopPile) {
	pile.CompletionTime.Merge(otherPile.CompletionTime)
	pile.ResponseTime.Merge(otherPile.ResponseTime)
}

//////////////////// EnvelopConfig ////////////////

// Exposes ValueConfig interface
type EnvelopConfig struct {
	ResponseTime   CountConfig `json:"responsetime"`
	CompletionTime CountConfig `json:"completiontime"`
}

func (config *EnvelopConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*EnvelopProfile))
}

func (config *EnvelopConfig) Decide(profile *EnvelopProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.ResponseTime.Decide(profile.ResponseTime), "ResponseTime")
	DecideChild(&current, config.CompletionTime.Decide(profile.CompletionTime), "CompletionTime")
	return current
}

func (config *EnvelopConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*EnvelopPile))
}

func (config *EnvelopConfig) Learn(pile *EnvelopPile) {
	config.CompletionTime.Learn(pile.CompletionTime)
	config.ResponseTime.Learn(pile.ResponseTime)
}

func (config *EnvelopConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*EnvelopConfig))
}

func (config *EnvelopConfig) Fuse(otherConfig *EnvelopConfig) {
	config.CompletionTime.Fuse(otherConfig.CompletionTime)
	config.ResponseTime.Fuse(otherConfig.ResponseTime)
}

func (config *EnvelopConfig) Prepare() {
	config.CompletionTime.Prepare()
	config.ResponseTime.Prepare()
}
