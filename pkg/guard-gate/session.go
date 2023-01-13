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
	"fmt"
	"net"
	"net/http"
	"time"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	utils "knative.dev/security-guard/pkg/guard-utils"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

const sessionKey = "GuardSession"

type session struct {
	sessionTicker *utils.Ticker
	gotResponse   bool
	alert         string                  // session alert
	reqTime       time.Time               // time when session was started
	respTime      time.Time               // time when session response came
	cancelFunc    context.CancelFunc      // cancel the session
	profile       spec.SessionDataProfile // maintainer of the session profile
	gateState     *gateState              // maintainer of the criteria and ctrl, include pod profile, gate stats and gate level alert
}

func newSession(state *gateState, cancel context.CancelFunc) *session {
	s := new(session)
	s.reqTime = time.Now()
	s.respTime = s.reqTime // indicates that we do not know the response time
	s.gateState = state
	s.cancelFunc = cancel
	s.sessionTicker = utils.NewTicker(utils.MinimumInterval)
	if err := s.sessionTicker.Parse("", podMonitorIntervalDefault); err != nil {
		pi.Log.Debugf("Error on Ticker Parse: %v", err)
	}
	state.addStat("Total")
	return s
}

func GetSessionFromContext(ctx context.Context) *session {
	defer func() {
		// This should never happen!
		if r := recover(); r != nil {
			pi.Log.Warnf("getSessionFromContext Recovered %s", r)
		}
	}()

	s, sExists := ctx.Value(ctxKey(sessionKey)).(*session)
	if !sExists {
		// This should never happen!
		return nil
	}
	return s
}

func (s *session) addSessionToContext(ctxIn context.Context) context.Context {
	return context.WithValue(ctxIn, ctxKey(sessionKey), s)
}

func (s *session) hasAlert() bool {
	return s.alert != ""
}

func (s *session) Cancel() {
	s.cancelFunc()
}

func (s *session) sessionEventLoop(ctx context.Context) {
	s.sessionTicker.Start()

	defer func() {
		s.sessionTicker.Stop()

		// Should we learn?
		if s.gateState.shouldLearn(s.hasAlert()) && s.gotResponse {
			s.gateState.addProfile(&s.profile)
		}

		// Should we alert?
		if s.gateState.hasAlert() {
			logAlert("Pod has an alert")
			s.gateState.addStat("BlockOnPod")
			return
		}
		if s.hasAlert() {
			logAlert(s.alert)
			s.gateState.addStat("SessionLevelAlert")
			return
		}
		// no alert
		if !s.gotResponse {
			pi.Log.Debugf("No Alert but completed before receiving a response!")
			s.gateState.addStat("NoResponse")
			return
		}
		if s.gateState.criteria == nil {
			pi.Log.Debugf("No Alert since no criteria")
			s.gateState.addStat("NoAlertNoCriteria")
			return
		}
		if !s.gateState.criteria.Active {
			pi.Log.Debugf("No Alert since criteria is not active")
			s.gateState.addStat("NoAlertCriteriaNotActive")
			return
		}
		pi.Log.Debugf("No Alert!")
		s.gateState.addStat("NoAlert")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.sessionTicker.Ch():
			s.screenEnvelop()
			s.screenPod()

			if s.gateState.shouldBlock() && (s.hasAlert() || s.gateState.hasAlert()) {
				s.Cancel()
				pi.Log.Debugf("Session Canceled")
				return
			}
			pi.Log.Debugf("Session Tick")
		}
	}
}

func (s *session) screenResponseBody(req *http.Response) {
	// TODO profile screenResponseBody in a future PR
	s.alert += s.gateState.decideRespBody(&s.profile.RespBody)
}

func (s *session) screenRequestBody(req *http.Request) {
	// TODO profile screenRequestBody in a future PR
	s.alert += s.gateState.decideReqBody(&s.profile.ReqBody)
}

func (s *session) screenEnvelop() {
	now := time.Now()
	respTime := s.respTime
	if !s.respTime.After(s.reqTime) {
		// we do not know the response time, lets assume it is now
		respTime = now
	}
	s.profile.Envelop.Profile(s.reqTime, respTime, now)

	s.alert += s.gateState.decideEnvelop(&s.profile.Envelop)
}

func (s *session) screenPod() {
	s.gateState.copyPodProfile(&s.profile.Pod)
}

func (s *session) screenRequest(req *http.Request) {
	// Request client and server identities
	cip, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		s.alert += fmt.Sprintf("illegal req.RemoteAddr %s", err.Error())
		s.gateState.addStat("ReqCipFault")
	}

	ip := net.ParseIP(cip)
	s.profile.Req.Profile(req, ip)

	s.alert += s.gateState.decideReq(&s.profile.Req)
}

func (s *session) screenResponse(resp *http.Response) {
	s.respTime = time.Now()
	s.profile.Resp.Profile(resp)

	s.alert += s.gateState.decideResp(&s.profile.Resp)
}
