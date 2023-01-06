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
	"net"
	"net/http"
)

//////////////////// ReqProfile ////////////////
// Does not monitor Trailers

// Exposes ValueProfile interface
type ReqProfile struct {
	ClientIp      IpSetProfile     `json:"cip"`           // 192.168.32.1
	HopIp         IpSetProfile     `json:"hopip"`         // 1.2.3.4
	Method        SetProfile       `json:"method"`        // GET
	Proto         SetProfile       `json:"proto"`         // "HTTP/1.1"
	MediaType     MediaTypeProfile `json:"mediatype"`     // "text/html"
	ContentLength CountProfile     `json:"contentlength"` // 0
	Url           UrlProfile       `json:"url"`
	Qs            QueryProfile     `json:"qs"`
	Headers       HeadersProfile   `json:"headers"`
}

func (profile *ReqProfile) profileI(args ...interface{}) {
	profile.Profile(args[0].(*http.Request), args[1].(net.IP))
}

func (profile *ReqProfile) Profile(req *http.Request, cip net.IP) {
	var hopIpStr string

	profile.ClientIp.ProfileIP(cip)

	// Future: Does not monitor rfc7239 "forwarded" headers
	if forwarded, ok := req.Header["X-Forwarded-For"]; ok {
		if numHops := len(forwarded); numHops > 0 {
			hopIpStr = forwarded[numHops-1]
		}
	}
	profile.HopIp.ProfileString(hopIpStr)

	profile.MediaType.Profile(req.Header.Get("Content-Type"))
	profile.Qs.Profile(req.URL.Query())

	profile.Method.ProfileString(req.Method)
	profile.Proto.ProfileString(req.Proto)
	profile.Url.Profile(req.URL.Path)
	profile.Headers.Profile(req.Header)

	length := req.ContentLength
	if length > 0 {
		var log2length uint8

		for length > 0 {
			log2length++
			length >>= 1
		}
		profile.ContentLength = CountProfile(log2length)
	}
}

//////////////////// ReqPile ////////////////

// Exposes ValuePile interface
type ReqPile struct {
	ClientIp      IpSetPile     `json:"cip"`           // 192.168.32.1
	HopIp         IpSetPile     `json:"hopip"`         // 1.2.3.4
	Method        SetPile       `json:"method"`        // GET
	Proto         SetPile       `json:"proto"`         // "HTTP/1.1"
	MediaType     MediaTypePile `json:"mediatype"`     // "text/html"
	ContentLength CountPile     `json:"contentlength"` // 0
	Url           UrlPile       `json:"url"`
	Qs            QueryPile     `json:"qs"`
	Headers       HeadersPile   `json:"headers"`
}

func (pile *ReqPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*ReqProfile))
}

func (pile *ReqPile) Add(profile *ReqProfile) {
	pile.ClientIp.Add(&profile.ClientIp)
	pile.HopIp.Add(&profile.HopIp)
	pile.Method.Add(&profile.Method)
	pile.Proto.Add(&profile.Proto)
	pile.MediaType.Add(&profile.MediaType)
	pile.ContentLength.Add(profile.ContentLength)
	pile.Url.Add(&profile.Url)
	pile.Qs.Add(&profile.Qs)
	pile.Headers.Add(&profile.Headers)
}

func (pile *ReqPile) Clear() {
	pile.ClientIp.Clear()
	pile.Method.Clear()
	pile.Proto.Clear()
	pile.MediaType.Clear()
	pile.ContentLength.Clear()
	pile.Url.Clear()
	pile.Qs.Clear()
	pile.Headers.Clear()
}

func (pile *ReqPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*ReqPile))
}

func (pile *ReqPile) Merge(otherPile *ReqPile) {
	pile.ClientIp.Merge(&otherPile.ClientIp)
	pile.Method.Merge(&otherPile.Method)
	pile.Proto.Merge(&otherPile.Proto)
	pile.MediaType.Merge(&otherPile.MediaType)
	pile.ContentLength.Merge(otherPile.ContentLength)
	pile.Url.Merge(&otherPile.Url)
	pile.Qs.Merge(&otherPile.Qs)
	pile.Headers.Merge(&otherPile.Headers)
}

//////////////////// ReqConfig ////////////////

// Exposes ValueConfig interface
type ReqConfig struct {
	ClientIp      IpSetConfig     `json:"cip"`           // subnets for external IPs (normally empty)
	HopIp         IpSetConfig     `json:"hopip"`         // subnets for external IPs
	Method        SetConfig       `json:"method"`        // GET
	Proto         SetConfig       `json:"proto"`         // "HTTP/1.1"
	MediaType     MediaTypeConfig `json:"mediatype"`     // "text/html"
	ContentLength CountConfig     `json:"contentlength"` // 0
	Url           UrlConfig       `json:"url"`
	Qs            QueryConfig     `json:"qs"`
	Headers       HeadersConfig   `json:"headers"`
}

func (config *ReqConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*ReqProfile))
}

func (config *ReqConfig) Decide(profile *ReqProfile) *Decision {
	var current *Decision
	DecideChild(&current, config.Url.Decide(&profile.Url), "Url")
	DecideChild(&current, config.Qs.Decide(&profile.Qs), "QueryString")
	DecideChild(&current, config.Headers.Decide(&profile.Headers), "Headers")
	DecideChild(&current, config.ClientIp.Decide(&profile.ClientIp), "ClientIp")
	DecideChild(&current, config.HopIp.Decide(&profile.HopIp), "HopIp")
	DecideChild(&current, config.Method.Decide(&profile.Method), "Method")
	DecideChild(&current, config.Proto.Decide(&profile.Proto), "Proto")
	DecideChild(&current, config.MediaType.Decide(&profile.MediaType), "MediaType")
	DecideChild(&current, config.ContentLength.Decide(profile.ContentLength), "ContentLength")
	return current
}

func (config *ReqConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*ReqPile))
}

func (config *ReqConfig) Learn(pile *ReqPile) {
	config.ClientIp.Learn(&pile.ClientIp)
	config.HopIp.Learn(&pile.HopIp)
	config.Method.Learn(&pile.Method)
	config.Proto.Learn(&pile.Proto)
	config.MediaType.Learn(&pile.MediaType)
	config.ContentLength.Learn(pile.ContentLength)
	config.Headers.Learn(&pile.Headers)
	config.Qs.Learn(&pile.Qs)
	config.Url.Learn(&pile.Url)
}

func (config *ReqConfig) Prepare() {
	config.ClientIp.Prepare()
	config.HopIp.Prepare()
	config.Method.Prepare()
	config.Proto.Prepare()
	config.MediaType.Prepare()
	config.ContentLength.Prepare()
	config.Headers.Prepare()
	config.Qs.Prepare()
	config.Url.Prepare()
}
