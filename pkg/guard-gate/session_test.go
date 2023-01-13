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

package guardgate

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/emicklei/go-restful"
	utils "knative.dev/security-guard/pkg/guard-utils"
)

var sessionCanceled int

func fakeSessionCancel() {
	sessionCanceled++
}

func Test_SessionInContext(t *testing.T) {
	ctx1 := context.Background()
	gs := fakeGateState()
	gs.loadConfig()

	t.Run("simple", func(t *testing.T) {
		s1 := newSession(gs, nil)
		s1.cancelFunc = fakeSessionCancel
		ctx2 := s1.addSessionToContext(ctx1)
		s2 := GetSessionFromContext(ctx2)

		if !reflect.DeepEqual(s1, s2) {
			t.Errorf("received a different session %v, want %v", s2, s1)
		}
		if s2.hasAlert() {
			t.Errorf("expected no alert")
		}

		sessionCanceled = 0
		if s2.Cancel(); sessionCanceled != 1 {
			t.Errorf("expected canceled")
		}

		bodyReader := strings.NewReader(`{"Username": "12124", "Password": "testinasg", "Channel": "M"}`)

		req, _ := http.NewRequest("POST", "/config", bodyReader)
		req.Header.Set("Content-Type", restful.MIME_JSON)
		s2.screenRequest(req)
		if !s2.hasAlert() {
			t.Errorf("expected alert")
		}
		s2.alert = ""
		req.RemoteAddr = "1.2.3.4:80"
		s2.screenRequest(req)
		if s2.hasAlert() {
			t.Errorf("expected no alert")
		}
		s2.gateState.criteria.Active = true
		s2.screenRequest(req)
		if !s2.hasAlert() {
			t.Errorf("expected alert")
		}
		s2.alert = ""
		s2.gateState.criteria.Active = false

		td, _ := time.ParseDuration("1s")
		time.Sleep(td)
		s2.screenEnvelop()
		if s2.hasAlert() {
			t.Errorf("expected no alert")
		}
		s2.gateState.criteria.Active = true
		s2.screenEnvelop()
		if !s2.hasAlert() {
			t.Errorf("expected alert")
		}
		s2.alert = ""
		s2.gateState.criteria.Active = false

		resp := &http.Response{ContentLength: 20}
		s2.screenResponse(resp)
		if s2.hasAlert() {
			t.Errorf("expected no alert")
		}
		s2.gateState.criteria.Active = true
		s2.screenResponse(resp)
		if !s2.hasAlert() {
			t.Errorf("expected alert")
		}
		s2.alert = ""
		s2.gateState.criteria.Active = false

		s2.screenPod()
		if s2.hasAlert() {
			t.Errorf("expected no alert")
		}

	})

}

func Test_session_sessionEventLoop(t *testing.T) {
	gs := fakeGateState()
	gs.loadConfig()
	gs.stat.Init()
	ctx, cancelFunction := context.WithCancel(context.Background())
	t.Run("simple", func(t *testing.T) {
		s := newSession(gs, nil)
		s.cancelFunc = cancelFunction
		gs.stat.Init()
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[NoResponse:1]" {
			t.Errorf("expected stat %s received %s", "map[NoResponse:1]", ret)
		}
		gs.stat.Init()
		s.gotResponse = true
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[NoAlertCriteriaNotActive:1]" {
			t.Errorf("expected stat %s received %s", "map[NoAlertCriteriaNotActive:1]", ret)
		}
		gs.stat.Init()
		s.gotResponse = true
		s.gateState.criteria.Active = true
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[NoAlert:1]" {
			t.Errorf("expected stat %s received %s", "map[NoAlert:1]", ret)
		}
		gs.stat.Init()
		gs.ctrl.Force = true
		gs.ctrl.Learn = true
		s.gotResponse = true
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[NoAlert:1]" {
			t.Errorf("expected stat %s received %s", "map[NoAlert:1]", ret)
		}

		gs.stat.Init()
		s.alert = "x"
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[SessionLevelAlert:1]" {
			t.Errorf("expected stat %s received %s", "map[SessionLevelAlert:1]", ret)
		}
		gs.stat.Init()
		gs.alert = "x"
		s.Cancel()
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[BlockOnPod:1]" {
			t.Errorf("expected stat %s received %s", "map[BlockOnPod:1]", ret)
		}
	})

}

func Test_session_sessionEventLoopTicker(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		ctx, cancelFunction := context.WithCancel(context.Background())
		gs := fakeGateState()
		gs.loadConfig()
		gs.stat.Init()
		s := newSession(gs, nil)
		s.cancelFunc = cancelFunction

		s.alert = "x"

		// lets rely on timeout
		s.sessionTicker = utils.NewTicker(100000)
		s.sessionTicker.Parse("", 100000)
		gs.stat.Init()
		gs.ctrl.Block = true
		s.sessionEventLoop(ctx)
		if ret := gs.stat.Log(); ret != "map[SessionLevelAlert:1]" {
			t.Errorf("expected stat %s received %s", "map[SessionLevelAlert:1]", ret)
		}
	})

}
