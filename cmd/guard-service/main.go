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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	utils "knative.dev/security-guard/pkg/guard-utils"

	"github.com/kelseyhightower/envconfig"
)

var log *zap.SugaredLogger

const (
	serviceIntervalDefault = 5 * time.Minute
)

type config struct {
	GuardServiceLogLevel string `split_words:"true" required:"false"`
	GuardServicePort     string `split_words:"true" required:"false"`
	GuardServiceInterval string `split_words:"true" required:"false"`
}

type learner struct {
	services        *services
	pileLearnTicker *utils.Ticker
}

// Common method used for parsing ns, sid, cmFlag from all requests
func (l *learner) baseHandler(query url.Values) (ns string, sid string, cmFlag bool, record *serviceRecord) {
	cmFlagSlice := query["cm"]
	sidSlice := query["sid"]
	nsSlice := query["ns"]
	if len(sidSlice) != 1 || len(nsSlice) != 1 || len(cmFlagSlice) > 1 {
		log.Infof("baseHandler wrong data sid %d ns %d cmFlag %d", len(sidSlice), len(nsSlice), len(cmFlagSlice))
		return
	}
	sid = utils.Sanitize(sidSlice[0])
	ns = utils.Sanitize(nsSlice[0])
	if len(cmFlagSlice) > 0 {
		cmFlag = (cmFlagSlice[0] == "true")
	}
	if strings.HasPrefix(sid, "ns-") {
		log.Infof("baseHandler illegal sid")
		sid = ""
		return
	}

	record = l.services.get(ns, sid, cmFlag)
	return
}

func (l *learner) fetchConfig(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" || req.URL.Path != "/config" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

	ns, sid, _, record := l.baseHandler(req.URL.Query())
	if record == nil || sid == "" || ns == "" {
		log.Infof("fetchConfig Missing data")
		http.Error(w, "Missing data", http.StatusBadRequest)
		return
	}

	buf, err := json.Marshal(record.guardianSpec)
	if err != nil {
		// should never happen
		log.Infof("Servicing fetchConfig error while JSON Marshal %v", err)
		http.Error(w, "Failed to marshal data", http.StatusInternalServerError)
		return
	}
	w.Write(buf)
}

func (l *learner) processPile(w http.ResponseWriter, req *http.Request) {
	var pile spec.SessionDataPile
	var err error
	ns, sid, _, record := l.baseHandler(req.URL.Query())
	if record == nil || sid == "" || ns == "" {
		log.Infof("processPile Missing data")
		http.Error(w, "processPile Missing data", http.StatusBadRequest)
		return
	}

	err = json.NewDecoder(req.Body).Decode(&pile)
	if err != nil {
		log.Infof("processPile error: %s", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	l.services.merge(record, &pile)

	log.Debugf("Successful setting record.wsgate")

	w.Write([]byte{})
}

func (l *learner) mainEventLoop(quit chan string) {
	log.Infof("l.pileLearnTicker %v", l.pileLearnTicker)

	for {
		select {
		case <-l.pileLearnTicker.Ch():
			l.services.tick()
		case reason := <-quit:
			log.Infof("mainEventLoop was asked to quit! - Reason: %s", reason)
			return
		}
	}
}

// Set network policies to ensure that only pods in your trust domain can use the service!
func _main() (*learner, *http.ServeMux, string, chan string) {
	var env config
	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process environment: %s\n", err.Error())
		os.Exit(1)
	}

	l := new(learner)
	l.pileLearnTicker = new(utils.Ticker)
	log = utils.CreateLogger(env.GuardServiceLogLevel)
	l.pileLearnTicker.Parse(env.GuardServiceInterval, serviceIntervalDefault)
	l.pileLearnTicker.Start()

	mux := http.NewServeMux()
	mux.HandleFunc("/config", l.fetchConfig)
	mux.HandleFunc("/pile", l.processPile)

	target := ":8888"
	if env.GuardServicePort != "" {
		target = fmt.Sprintf(":%s", env.GuardServicePort)
	}

	quit := make(chan string)

	log.Infof("Starting guard-learner on %s", target)
	return l, mux, target, quit
}

func main() {
	l, mux, target, quit := _main()

	l.services = newServices()

	// start a mainLoop
	go l.mainEventLoop(quit)

	err := http.ListenAndServe(target, mux)
	log.Infof("Failed to start %v", err)
	quit <- "ListenAndServe failed"
}
