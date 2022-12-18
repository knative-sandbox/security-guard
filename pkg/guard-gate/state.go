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
	"crypto/x509"
	"os"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	utils "knative.dev/security-guard/pkg/guard-utils"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

func logAlert(alert string) {
	pi.Log.Infof("SECURITY ALERT! %s", alert)
}

type gateState struct {
	cancelFunc context.CancelFunc      // cancel the entire reverse proxy
	ctrl       *spec.Ctrl              // gate Ctrl
	criteria   *spec.SessionDataConfig // gate Criteria
	stat       utils.Stat              // gate stats
	alert      string                  // gate alert
	monitorPod bool                    // should gate profile the pod?
	pod        spec.PodProfile         // pod profile
	srv        *gateClient             // maintainer of the pile, include client to the guard-service & kubeApi
	certPool   *x509.CertPool          // rootCAs
}

func (gs *gateState) init(cancelFunc context.CancelFunc, monitorPod bool, guardServiceUrl string, sid string, ns string, useCm bool) {
	var err error
	gs.stat.Init()
	gs.monitorPod = monitorPod
	gs.cancelFunc = cancelFunc
	gs.srv = NewGateClient(guardServiceUrl, sid, ns, useCm)

	gs.certPool, err = x509.SystemCertPool()
	if err != nil {
		gs.certPool = x509.NewCertPool()
	}

	if rootCA := os.Getenv("ROOT_CA"); rootCA != "" {
		if ok := gs.certPool.AppendCertsFromPEM([]byte(rootCA)); ok {
			pi.Log.Infof("TLS: Success adding ROOT_CA")
		} else {
			pi.Log.Infof("TLS: Failed to AppendCertsFromPEM from ROOT_CA")
		}
	}
}

func (gs gateState) start() {
	// Skip during simulations
	if len(gs.srv.ns) > 0 {
		// initializtion that cant be tested due to use of KubeAMgr
		gs.srv.initKubeMgr()
	}
	gs.srv.initHttpClient(gs.certPool)
}

// loadConfig is called periodically to load updated configuration from a Guardian
func (gs *gateState) loadConfig() {
	pi.Log.Infof("Loading Guardian")
	// loadGuardian never returns nil!
	g := gs.srv.loadGuardian()

	if gs.ctrl = g.Control; gs.ctrl == nil {
		gs.ctrl = new(spec.Ctrl)
	}

	// Set the correct criteria
	var criteria *spec.SessionDataConfig
	if gs.ctrl.Auto {
		criteria = g.Learned
	} else {
		criteria = g.Configured
	}
	if criteria == nil {
		criteria = new(spec.SessionDataConfig)
	}
	criteria.Prepare()
	gs.criteria = criteria
}

// flushPile is called periodically to send the pile to the guard-service
func (gs *gateState) flushPile() {
	gs.srv.reportPile()
}

// addProfile is called every time we have a new profile ready to be added to a pile
func (gs *gateState) addProfile(profile *spec.SessionDataProfile) {
	gs.srv.addToPile(profile)
}

// Methods to profile and decide base don pod data.
// Enables the POD profile to be copied to the sessio  profile for reporting to pile.

// profileAndDecidePod is called periodically to profile the pod and decide if to raise an alert
func (gs *gateState) profileAndDecidePod() {
	if !gs.monitorPod {
		return
	}
	//First profile
	gs.pod.Profile()

	// Now decide
	// Current behaviour is latching the alert forever
	// This makes sense from security standpoint as the pod is now considered contaminated
	// If we are blocking, this means we will simply keep blocking all requests forever
	// Therefore we terminate the reverse proxy
	// Future - add more controls to decide what to do in this situation
	if gs.criteria != nil && gs.criteria.Active {
		decision := gs.criteria.Pod.Decide(&gs.pod)
		if decision != nil {
			gs.addStat("PodAlert")
			gs.alert = decision.String("Pod  -> ")

			logAlert(gs.alert)
			// terminate the reverse proxy
			gs.cancelFunc()
		}
	}
}

// if pod is monitored, copy its profile to the session profile
func (gs *gateState) copyPodProfile(pp *spec.PodProfile) {
	if !gs.monitorPod {
		return
	}
	gs.pod.DeepCopyInto(pp)
}

// The following decide...() methods allow sessions to provide parts of the profile as they are being formed
// the profiles are being decided and alerts is set accordingly.

// returns the alert text if needed
func (gs *gateState) decideReq(rp *spec.ReqProfile) string {
	if gs.criteria != nil && gs.criteria.Active {
		if decision := gs.criteria.Req.Decide(rp); decision != nil {
			gs.addStat("ReqAlert")
			return decision.String("HttpRequest -> ")
		}
	}
	return ""
}

// returns the alert text if needed
func (gs *gateState) decideResp(rp *spec.RespProfile) string {
	if gs.criteria != nil && gs.criteria.Active {
		if decision := gs.criteria.Resp.Decide(rp); decision != nil {
			gs.addStat("RespAlert")
			return decision.String("HttpResponse  -> ")
		}
	}
	return ""
}

// returns the alert text if needed
func (gs *gateState) decideReqBody(bp *spec.BodyProfile) string {
	if gs.criteria != nil && gs.criteria.Active {
		if decision := gs.criteria.ReqBody.Decide(bp); decision != nil {
			gs.addStat("ReqBodyAlert")
			return decision.String("HttpRequestBody -> ")
		}
	}
	return ""
}

// returns the alert text if needed
func (gs *gateState) decideRespBody(bp *spec.BodyProfile) string {
	if gs.criteria != nil && gs.criteria.Active {
		if decision := gs.criteria.RespBody.Decide(bp); decision != nil {
			gs.addStat("RespBodyAlert")
			return decision.String("HttpResponseBody  -> ")
		}
	}
	return ""
}

// returns the alert text if needed
func (gs *gateState) decideEnvelop(ep *spec.EnvelopProfile) string {
	if gs.criteria != nil && gs.criteria.Active {
		if decision := gs.criteria.Envelop.Decide(ep); decision != nil {
			gs.addStat("EnvelopAlert")
			return decision.String("Envelop  -> ")
		}
	}
	return ""
}

// generic methods:

// advance statistics counter
func (gs *gateState) addStat(key string) {
	gs.stat.Add(key)
}

// are we blocking request on alerts?
func (gs *gateState) shouldBlock() bool {
	return gs.ctrl.Block
}

// do we have a gate level alert?
func (gs *gateState) hasAlert() bool {
	return gs.alert != ""
}

// should we be learning?
func (gs *gateState) shouldLearn(sessionAlert bool) bool {
	// dio we have an alert?
	alert := (gs.alert != "") || !sessionAlert
	return gs.ctrl.Learn && (!alert || gs.ctrl.Force)
}
