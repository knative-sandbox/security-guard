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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	guardgate "knative.dev/security-guard/pkg/guard-gate"
	utils "knative.dev/security-guard/pkg/guard-utils"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

type config struct {
	NumServices          int    `split_words:"true" required:"false"`
	NumInstances         int    `split_words:"true" required:"false"`
	NumRequests          int    `split_words:"true" required:"false"`
	GuardUrl             string `split_words:"true" required:"false"`
	LogLevel             string `split_words:"true" required:"false"`
	PodMonitorInterval   string `split_words:"true" required:"false"`
	ReportPileInterval   string `split_words:"true" required:"false"`
	GuardianLoadInterval string `split_words:"true" required:"false"`
}

func main() {
	var env config
	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process environment: %s\n", err.Error())
		return
	}
	utils.CreateLogger(env.LogLevel)

	plugConfig := make(map[string]string)
	plugConfig["monitor-pod"] = "false" // default when used as a standalone
	plugConfig["use-cm"] = "false"

	NumServices := env.NumServices
	NumInstances := env.NumInstances
	NumRequests := env.NumRequests
	if NumServices == 0 {
		NumServices = 100
	}
	if NumInstances == 0 {
		NumInstances = 10
	}
	if NumRequests == 0 {
		NumRequests = 1000
	}

	pi.Log.Infof("env.GuardUrl %s\n", env.GuardUrl)
	if env.GuardUrl == "" {
		env.GuardUrl = "http://guard-service.knative-serving"
	} else {
		plugConfig["guard-url"] = env.GuardUrl
	}

	fmt.Printf("utils.MinimumInterval %d\n", utils.MinimumInterval)
	utils.MinimumInterval = 5 * time.Millisecond
	fmt.Printf("utils.MinimumInterval %d\n", utils.MinimumInterval)
	rand.Seed(time.Now().UnixNano())
	guardGates := make([][]pi.RoundTripPlug, NumServices)
	randomSid := (time.Now().UnixNano() % 0x1000000)
	for svc := 0; svc < NumServices; svc++ {
		guardGates[svc] = make([]pi.RoundTripPlug, NumInstances)
		sid := fmt.Sprintf("simulate-%x-%x", randomSid, svc)
		for ins := 0; ins < NumInstances; ins++ {
			plugConfig["guardian-load-interval"] = fmt.Sprintf("%dns", rand.Intn(100000000000))
			plugConfig["report-pile-interval"] = fmt.Sprintf("%dns", rand.Intn(10000000))
			plugConfig["pod-monitor-interval"] = fmt.Sprintf("%dns", rand.Intn(100000000000))
			fmt.Printf("plugConfig %v\n", plugConfig)
			guardGates[svc][ins] = guardgate.NewGate()
			guardGates[svc][ins].Init(context.Background(), plugConfig, sid, "", pi.Log)
			defer guardGates[svc][ins].Shutdown()
		}
	}

	defer utils.SyncLogger()
	body := map[string][]string{
		"abc": {"ccc", "dddd"},
		"www": {"aaa", "bbb"},
	}

	jsonBytes, _ := json.Marshal(body)

	rand.Seed(time.Now().UnixNano())
	for {
		svc := rand.Intn(NumServices)
		ins := rand.Intn(NumInstances)
		reqs := rand.Intn(NumRequests)
		for i := 0; i <= reqs; i++ {
			// request handling
			req := httptest.NewRequest("GET", "/", bytes.NewReader(jsonBytes))
			req, err := guardGates[svc][ins].ApproveRequest(req)
			if err != nil {
				pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
				continue
			}

			// response handling
			resp := new(http.Response)
			_, err = guardGates[svc][ins].ApproveResponse(req, resp)
			if err != nil {
				pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
				continue
			}

			// cancel handling

			s := guardgate.GetSessionFromContext(req.Context())
			if s == nil { // This should never happen!
				pi.Log.Infof("Cant cancel simulation Missing context!")
				continue
			}
			s.Cancel()
		}
	}
	/*
		ticker := time.NewTicker(1000 * time.Millisecond)

		for range ticker.C {

			for svc := 0; svc < NumServices; svc++ {
				for ins := 0; ins < NumInstances; ins++ {
					for i := 0; i < NumRequests; i++ {
						// request handling
						req := httptest.NewRequest("GET", "/", bytes.NewReader(jsonBytes))
						req, err := guardGates[svc][ins].ApproveRequest(req)
						if err != nil {
							pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
							continue
						}

						// response handling
						resp := new(http.Response)
						_, err = guardGates[svc][ins].ApproveResponse(req, resp)
						if err != nil {
							pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
							continue
						}

						// cancel handling

						s := guardgate.GetSessionFromContext(req.Context())
						if s == nil { // This should never happen!
							pi.Log.Infof("Cant cancel simulation Missing context!")
							continue
						}
						s.Cancel()
					}
				}
			}
		}
	*/
}
