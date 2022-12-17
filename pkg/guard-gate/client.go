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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"sync"

	"net/http"
	"os"
	"path"
	"time"

	"knative.dev/control-protocol/pkg/certificates"
	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	guardKubeMgr "knative.dev/security-guard/pkg/guard-kubemgr"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

type httpClientInterface interface {
	ReadToken(audience string)
	Do(req *http.Request) (*http.Response, error)
}

type httpClient struct {
	client           http.Client
	token            string
	tokenRefreshTime time.Time
	missingToken     bool
}

func (hc *httpClient) Do(req *http.Request) (*http.Response, error) {
	if !hc.missingToken {
		// add authorization header - optional for this revision of guard
		req.Header.Add("Authorization", "Bearer "+hc.token)
	}

	return hc.client.Do(req)
}

func (hc *httpClient) ReadToken(audience string) {
	// If not yet tokenRefreshTime, skip reading
	now := time.Now()
	if hc.tokenRefreshTime.After(now) {
		return
	}
	// refresh in 100 minuets
	hc.tokenRefreshTime = now.Add(100 * time.Minute)

	// TODO: replace  "/var/run/secrets/tokens" with sharedMain.QPOptionTokenDirPath once merged.
	b, err := os.ReadFile(path.Join("/var/run/secrets/tokens", audience))

	if err != nil {
		pi.Log.Infof("Token %s is missing - working without token", audience)
		hc.missingToken = true
		return
	}
	hc.token = string(b)
	hc.missingToken = false

	pi.Log.Debugf("Refreshing client token - next refresh at %s", hc.tokenRefreshTime.String())
}

type gateClient struct {
	guardServiceUrl string
	sid             string
	ns              string
	useCm           bool
	httpClient      httpClientInterface
	pile            spec.SessionDataPile
	pileMutex       sync.Mutex
	kubeMgr         guardKubeMgr.KubeMgrInterface
}

func NewGateClient(guardServiceUrl string, sid string, ns string, useCm bool) *gateClient {
	srv := new(gateClient)
	srv.kubeMgr = guardKubeMgr.NewKubeMgr()
	srv.guardServiceUrl = guardServiceUrl
	srv.sid = sid
	srv.ns = ns
	srv.useCm = useCm

	srv.clearPile()

	return srv
}

func (srv *gateClient) initKubeMgr() {
	// initializtion that cant be tested due to use of KubeAMgr
	srv.kubeMgr.InitConfigs()
}

func (srv *gateClient) initHttpClient(certPool *x509.CertPool) {
	client := new(httpClient)
	pi.Log.Infof("initHttpClient using ServerName %s\n", certificates.FakeDnsName)
	client.client.Transport = &http.Transport{
		MaxConnsPerHost:     0,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		TLSClientConfig: &tls.Config{
			ServerName: certificates.FakeDnsName,
			RootCAs:    certPool,
		},
	}
	srv.httpClient = client
	srv.httpClient.ReadToken(guardKubeMgr.ServiceAudience)
}

func (srv *gateClient) reportPile() {
	if srv.pile.Count == 0 {
		return
	}
	defer srv.clearPile()

	srv.httpClient.ReadToken(guardKubeMgr.ServiceAudience)

	// protect pile internals read/write
	srv.pileMutex.Lock()
	postBody, marshalErr := json.Marshal(srv.pile)
	srv.pileMutex.Unlock()

	if marshalErr != nil {
		// should never happen
		pi.Log.Infof("Error during marshal: %v", marshalErr)
		return
	}
	reqBody := bytes.NewBuffer(postBody)
	req, err := http.NewRequest(http.MethodPost, srv.guardServiceUrl+"/pile", reqBody)
	if err != nil {
		pi.Log.Infof("Http.NewRequest error %v", err)
		return
	}
	query := req.URL.Query()
	query.Add("sid", srv.sid)
	query.Add("ns", srv.ns)
	if srv.useCm {
		query.Add("cm", "true")
	}
	req.URL.RawQuery = query.Encode()
	pi.Log.Infof("Reporting a pile with pileCount %d records to guard-service", srv.pile.Count)

	res, postErr := srv.httpClient.Do(req)
	if postErr != nil {
		pi.Log.Infof("httpClient.Do error %v", postErr)
		return
	}
	if res.Body != nil {
		defer res.Body.Close()
		body, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			pi.Log.Infof("Response error %v", readErr)
			return
		}
		if len(body) != 0 {
			pi.Log.Infof("guard-service response is %s", string(body))
		}
	}
}

func (srv *gateClient) addToPile(profile *spec.SessionDataProfile) {
	// protect pile internals read/write
	srv.pileMutex.Lock()
	srv.pile.Add(profile)
	srv.pileMutex.Unlock()

	pi.Log.Debugf("Learn - add to pile! pileCount %d", srv.pile.Count)
}

func (srv *gateClient) clearPile() {
	srv.pileMutex.Lock()
	srv.pile.Clear()
	srv.pileMutex.Unlock()
}

func (srv *gateClient) loadGuardian() *spec.GuardianSpec {
	wsGate := srv.loadGuardianFromService()
	if wsGate == nil {
		// never return nil!
		wsGate = srv.kubeMgr.GetGuardian(srv.ns, srv.sid, srv.useCm, true)
	}
	return wsGate
}

func (srv *gateClient) loadGuardianFromService() *spec.GuardianSpec {
	srv.httpClient.ReadToken(guardKubeMgr.ServiceAudience)

	req, err := http.NewRequest(http.MethodGet, srv.guardServiceUrl+"/config", nil)
	if err != nil {
		pi.Log.Infof("loadGuardianFromService Http.NewRequest error %v", err)
		return nil
	}
	query := req.URL.Query()
	query.Add("sid", srv.sid)
	query.Add("ns", srv.ns)
	if srv.useCm {
		query.Add("cm", "true")
	}
	req.URL.RawQuery = query.Encode()

	res, err := srv.httpClient.Do(req)

	if err != nil {
		pi.Log.Infof("loadGuardianFromService httpClient.Do error %v", err)
		return nil
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		pi.Log.Infof("loadGuardianFromService Response error %v", err)
		return nil
	}
	if len(body) == 0 {
		pi.Log.Infof("loadGuardianFromService Response empty")
		return nil
	}
	pi.Log.Debugf("loadGuardianFromService: accepted guardian from guard-service")

	g := new(spec.GuardianSpec)
	jsonErr := json.Unmarshal(body, g)
	if jsonErr != nil {
		pi.Log.Infof("loadGuardianFromService GuardianSpec: unmarshel error %v", jsonErr)
		return nil
	}
	return g
}
