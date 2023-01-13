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
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	pi "knative.dev/security-guard/pkg/pluginterfaces"

	utils "knative.dev/security-guard/pkg/guard-utils"
)

const plugVersion string = "0.3"
const plugName string = "guard"

const (
	guardianLoadIntervalDefault = 5 * time.Minute
	reportPileIntervalDefault   = 10 * time.Second
	podMonitorIntervalDefault   = 5 * time.Second
)

var errSecurity error = errors.New("security blocked by guard")

type ctxKey string

type plug struct {
	name    string
	version string

	// guard gate plug specifics
	gateState          *gateState    // maintainer of the criteria and ctrl, include pod profile, gate stats and gate level alert
	guardianLoadTicker *utils.Ticker // tick to gateState.loadConfig() gateState
	reportPileTicker   *utils.Ticker // tick to gateState.flushPile()
	podMonitorTicker   *utils.Ticker // tick to gateState.profileAndDecidePod()
}

func (p *plug) Shutdown() {
	pi.Log.Debugf("%s: Shutdown", p.name)
	p.gateState.flushPile()
}

func (p *plug) PlugName() string {
	return p.name
}

func (p *plug) PlugVersion() string {
	return p.version
}

func (p *plug) ApproveRequest(req *http.Request) (*http.Request, error) {
	ctx, cancelFunction := context.WithCancel(req.Context())

	s := newSession(p.gateState, cancelFunction) // maintainer of the profile

	// Req
	s.screenEnvelop()
	s.screenRequest(req)
	s.screenRequestBody(req)

	if p.gateState.shouldBlock() && (s.hasAlert() || p.gateState.hasAlert()) {
		p.gateState.addStat("BlockOnRequest")
		cancelFunction()
		return nil, errSecurity
	}

	// Request not blocked
	ctx = s.addSessionToContext(ctx)
	ctx = context.WithValue(ctx, ctxKey("GuardSession"), s)

	req = req.WithContext(ctx)

	//goroutine to accompany the request
	go s.sessionEventLoop(ctx)

	return req, nil
}

func (p *plug) ApproveResponse(req *http.Request, resp *http.Response) (*http.Response, error) {
	s := GetSessionFromContext(req.Context())
	if s == nil { // This should never happen!
		pi.Log.Infof("%s ........... Blocked During Response! Missing context!", p.name)
		return nil, errors.New("missing context")
	}

	s.gotResponse = true

	s.screenResponse(resp)
	s.screenResponseBody(resp)
	s.screenEnvelop()
	if p.gateState.shouldBlock() && (s.hasAlert() || p.gateState.hasAlert()) {
		s.Cancel()
		p.gateState.addStat("BlockOnResponse")
		return nil, errSecurity
	}

	return resp, nil
}

func (p *plug) guardMainEventLoop(ctx context.Context) {
	p.guardianLoadTicker.Start()
	p.reportPileTicker.Start()
	p.podMonitorTicker.Start()
	defer func() {
		p.guardianLoadTicker.Stop()
		p.reportPileTicker.Stop()
		p.podMonitorTicker.Stop()
		p.gateState.flushPile()
		pi.Log.Infof("%s: Done with the following statistics: %s", plugName, p.gateState.stat.Log())
	}()

	for {
		select {
		// Always finish guard here!
		case <-ctx.Done():
			return

		// Periodically get an updated Guardian
		case <-p.guardianLoadTicker.Ch():
			p.gateState.loadConfig()

		// Periodically send pile to the guard-service
		case <-p.reportPileTicker.Ch():
			p.gateState.flushPile()

		// Periodically profile of the pod
		case <-p.podMonitorTicker.Ch():
			p.gateState.profileAndDecidePod()
		}
	}
}
func (p *plug) preInit(ctxIn context.Context, c map[string]string, sid string, ns string, logger pi.Logger) (ctxOut context.Context, cancelFunction context.CancelFunc, tlsActive bool) {
	var ok bool
	var v string
	var loadInterval, pileInterval, monitorInterval string

	ctxOut, cancelFunction = context.WithCancel(ctxIn)

	// Defaults used without config when used as a qpoption
	useCm := false
	monitorPod := true

	guardServiceUrl := "http://guard-service.knative-serving"
	if rootCA := os.Getenv("ROOT_CA"); rootCA != "" {
		guardServiceUrl = "https://guard-service.knative-serving"
		tlsActive = true
	}

	if c != nil {
		if v, ok = c["guard-url"]; ok && v != "" {
			// use default
			guardServiceUrl = v
		}

		if v, ok = c["use-cm"]; ok && strings.EqualFold(v, "true") {
			useCm = true
		}

		if v, ok = c["monitor-pod"]; ok && !strings.EqualFold(v, "true") {
			monitorPod = false
		}
		loadInterval = c["guardian-load-interval"]
		pileInterval = c["report-pile-interval"]
		monitorInterval = c["pod-monitor-interval"]
	}

	p.guardianLoadTicker = utils.NewTicker(utils.MinimumInterval)
	p.reportPileTicker = utils.NewTicker(utils.MinimumInterval)
	p.podMonitorTicker = utils.NewTicker(utils.MinimumInterval)

	p.guardianLoadTicker.Parse(loadInterval, guardianLoadIntervalDefault)
	p.reportPileTicker.Parse(pileInterval, reportPileIntervalDefault)
	p.podMonitorTicker.Parse(monitorInterval, podMonitorIntervalDefault)

	pi.Log.Debugf("guard-gate configuration: sid=%s, ns=%s, useCm=%t, guardUrl=%s, p.monitorPod=%t, guardian-load-interval %v, report-pile-interval %v, pod-monitor-interval %v",
		sid, ns, useCm, guardServiceUrl, monitorPod, loadInterval, pileInterval, monitorInterval)

	// serviceName should never be "ns.{namespace}" as this is a reserved name
	if strings.HasPrefix(sid, "ns.") {
		// mandatory
		panic("Ileal serviceName - ns.{Namespace} is reserved")
	}

	p.gateState = new(gateState)
	p.gateState.init(cancelFunction, monitorPod, guardServiceUrl, sid, ns, useCm)
	return
}

func (p *plug) Init(ctx context.Context, c map[string]string, sid string, ns string, logger pi.Logger) context.Context {
	newCtx, _, tlsActive := p.preInit(ctx, c, sid, ns, logger)

	// cant be tested as depend on KubeMgr
	tokenActive := p.gateState.start()

	pi.Log.Infof("guard-gate: TLS %t, Token %t", tlsActive, tokenActive)

	p.gateState.loadConfig()
	p.gateState.profileAndDecidePod()

	//goroutine for Guard instance
	go p.guardMainEventLoop(newCtx)

	return newCtx
}

func NewGate() (p *plug) {
	p = new(plug)
	p.version = plugVersion
	p.name = plugName
	return
}

func init() {
	gate := NewGate()
	pi.RegisterPlug(gate)
}
