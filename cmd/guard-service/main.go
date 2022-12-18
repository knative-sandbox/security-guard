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

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	utils "knative.dev/security-guard/pkg/guard-utils"

	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

const (
	serviceIntervalDefault = 5 * time.Minute
)

var totalPiles uint64
var totalProfiles uint64
var startTime time.Time

type config struct {
	GuardServiceLogLevel string   `split_words:"true" required:"false"`
	GuardServiceInterval string   `split_words:"true" required:"false"`
	GuardServiceAuth     bool     `split_words:"true" required:"false"`
	GuardServiceLabels   []string `split_words:"true" required:"false"`
	GuardServiceTls      bool     `split_words:"true" required:"false"`
}

type learner struct {
	services        *services
	pileLearnTicker *utils.Ticker
}

var env config

func (l *learner) authenticate(req *http.Request) (sid string, ns string, err error) {
	token := req.Header.Get("Authorization")
	if !strings.HasPrefix(token, "Bearer ") {
		err = fmt.Errorf("missing token")
		return
	}
	token = token[7:]
	sid, ns, err = l.services.kmgr.TokenData(token, env.GuardServiceLabels)
	if err != nil {
		err = fmt.Errorf("cant verify token %w", err)
		return
	}
	if sid == "ns-"+ns {
		err = fmt.Errorf("token of a service with illegal name %s", sid)
		return
	}
	return
}

// Common method used for parsing ns, sid, cmFlag from all requests
func (l *learner) queryData(query url.Values) (cmFlag bool, sid string, ns string, err error) {
	cmFlagSlice := query["cm"]
	sidSlice := query["sid"]
	nsSlice := query["ns"]

	if len(sidSlice) != 1 || len(nsSlice) != 1 || len(cmFlagSlice) > 1 {
		err = fmt.Errorf("query has wrong cmflag/sid/ns length")
		return
	}

	// extract and sanitize sid and ns
	sid = utils.Sanitize(sidSlice[0])
	ns = utils.Sanitize(nsSlice[0])

	if sid == "ns-"+ns {
		err = fmt.Errorf("query sid of a service with illegal name that starts with ns-")
		return
	}

	if len(sid) < 1 {
		err = fmt.Errorf("query missing sid")
		return
	}

	// extract and sanitize cmFlag
	if len(cmFlagSlice) > 0 {
		cmFlag = (cmFlagSlice[0] == "true")
	}

	return
}

func (l *learner) baseHandler(w http.ResponseWriter, req *http.Request) (record *serviceRecord, err error) {
	var sid, ns, querySid, queryNs string
	var cmFlag bool

	cmFlag, querySid, queryNs, err = l.queryData(req.URL.Query())
	if err != nil {
		pi.Log.Infof("baseHandler queryData failed with %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pi.Log.Debugf("queryData ns %s, sid %s cmFlag %t", queryNs, querySid, cmFlag)

	if env.GuardServiceAuth {
		sid, ns, err = l.authenticate(req)
		if err != nil {
			pi.Log.Infof("baseHandler authenticate failed with %v", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		pi.Log.Debugf("Authorized ns %s, sid %s", ns, sid)
	} else {
		sid = querySid
		ns = queryNs
		pi.Log.Debugf("Authorization skipped ns %s, sid %s", ns, sid)
	}

	// get session record, create one if does not exist
	record = l.services.get(ns, sid, cmFlag)
	if record == nil {
		// should never happen
		err = fmt.Errorf("no record created")
		pi.Log.Infof("internal error %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	pi.Log.Debugf("record found for ns %s, sid %s", ns, sid)
	return
}

func (l *learner) fetchConfig(w http.ResponseWriter, req *http.Request) {
	record, err := l.baseHandler(w, req)
	if err != nil {
		return
	}

	if req.Method != "GET" || req.URL.Path != "/config" {
		http.Error(w, "404 not found.", http.StatusNotFound)
	}

	buf, err := json.Marshal(record.guardianSpec)
	if err != nil {
		// should never happen
		pi.Log.Infof("Servicing fetchConfig error while JSON Marshal %v", err)
		http.Error(w, "Failed to marshal data", http.StatusInternalServerError)
		return
	}
	pi.Log.Debugf("Servicing fetchConfig success")
	w.Write(buf)
}

func (l *learner) processPile(w http.ResponseWriter, req *http.Request) {
	record, err := l.baseHandler(w, req)
	if err != nil {
		return
	}
	if req.Method != "POST" || req.URL.Path != "/pile" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	if req.ContentLength == 0 || req.Body == nil {
		http.Error(w, "400 not found.", http.StatusBadRequest)
		return
	}

	var pile spec.SessionDataPile
	err = json.NewDecoder(req.Body).Decode(&pile)
	if err != nil {
		pi.Log.Infof("processPile error: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	totalPiles++
	totalProfiles += uint64(pile.Count)
	elapsed := time.Since(startTime)

	l.services.merge(record, &pile)

	pi.Log.Debugf("Successful merging pile totalPiles %d totalProfiles %d time %d", totalPiles, totalProfiles, elapsed)
	if elapsed > 1000000000 {
		pi.Log.Infof("Successful merging pile totalPiles %d totalProfiles %d time %d", totalPiles, totalProfiles, elapsed)
		startTime = time.Now()
		totalPiles = 0
		totalProfiles = 0
	}
	w.Write([]byte{})
}

func (l *learner) mainEventLoop(quit chan string) {
	for {
		select {
		case <-l.pileLearnTicker.Ch():
			l.services.tick()
		case reason := <-quit:
			pi.Log.Infof("mainEventLoop was asked to quit! - Reason: %s", reason)
			return
		}
	}
}

// Set network policies to ensure that only pods in your trust domain can use the service!
func preMain(minimumInterval time.Duration) (*learner, *http.ServeMux, string, chan string) {
	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process environment: %s\n", err.Error())
		os.Exit(1)
	}
	utils.CreateLogger(env.GuardServiceLogLevel)

	l := new(learner)
	l.pileLearnTicker = utils.NewTicker(minimumInterval)
	l.pileLearnTicker.Parse(env.GuardServiceInterval, serviceIntervalDefault)
	l.pileLearnTicker.Start()

	l.services = newServices()

	mux := http.NewServeMux()
	mux.HandleFunc("/config", l.fetchConfig)
	mux.HandleFunc("/pile", l.processPile)

	target := ":8888"

	quit := make(chan string)

	pi.Log.Infof("Starting guard-service on %s", target)
	return l, mux, target, quit
}

func main() {
	var err error
	l, mux, target, quit := preMain(utils.MinimumInterval)
	startTime = time.Now()

	// cant be tested due to KubeMgr
	l.services.start()
	// start a mainLoop
	go l.mainEventLoop(quit)

	if env.GuardServiceTls {
		pi.Log.Infof("TLS turned on")
		srv := &http.Server{
			Addr:    target,
			Handler: mux,
			TLSConfig: &tls.Config{
				MinVersion:               tls.VersionTLS12,
				PreferServerCipherSuites: true,
			},
		}

		_, err = os.Stat("/secrets/public-cert.pem")
		if err == nil {
			err = srv.ListenAndServeTLS("/secrets/public-cert.pem", "/secrets/private-key.pem")
		} else {
			if os.IsNotExist(err) {
				// Since the secret keys should be at some point renamed, if we are here lets try the new names
				err = srv.ListenAndServeTLS("/secrets/tls.crt", "/secrets/tls.key")
			}
		}
	} else {
		pi.Log.Infof("TLS turned off")
		err = http.ListenAndServe(target, mux)
	}
	pi.Log.Infof("Using target: %s - Failed to start %v", target, err)
	quit <- "ListenAndServe failed"
}
