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
	"sync"
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

var NumServices, NumInstances, NumRequests int
var jsonBytes []byte
var wg sync.WaitGroup

func simulateReqRespSession(g pi.RoundTripPlug) {
	// request handling
	req := httptest.NewRequest("GET", "/", bytes.NewReader(jsonBytes))
	req, err := g.ApproveRequest(req)
	if err != nil {
		pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
		return
	}

	// response handling
	resp := new(http.Response)
	_, err = g.ApproveResponse(req, resp)
	if err != nil {
		pi.Log.Infof("Error during simulation ApproveRequest %v\n", err)
		return
	}

	// cancel handling

	s := guardgate.GetSessionFromContext(req.Context())
	if s == nil { // This should never happen!
		pi.Log.Infof("Cant cancel simulation Missing context!")
		return
	}
	s.Cancel()
}

func simulate(g pi.RoundTripPlug) {
	defer wg.Done()
	ticker := time.NewTicker(1000 * time.Millisecond)

	for range ticker.C {
		reqs := rand.Intn(NumRequests)
		for i := 0; i <= reqs; i++ {
			simulateReqRespSession(g)
		}
	}

}

func main() {
	var env config

	if err := envconfig.Process("", &env); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to process environment: %s\n", err.Error())
		return
	}
	utils.CreateLogger(env.LogLevel)
	defer utils.SyncLogger()

	rand.Seed(time.Now().UnixNano())

	plugConfig := make(map[string]string)
	plugConfig["monitor-pod"] = "false" // default when used as a standalone
	plugConfig["use-cm"] = "false"

	NumServices = env.NumServices
	NumInstances = env.NumInstances
	NumRequests = env.NumRequests
	if NumServices == 0 {
		NumServices = 10
	}
	if NumInstances == 0 {
		NumInstances = 100
	}
	if NumRequests == 0 {
		NumRequests = 100
	}

	pi.Log.Infof("env.GuardUrl %s\n", env.GuardUrl)
	if env.GuardUrl == "" {
		env.GuardUrl = "http://guard-service.knative-serving"
	} else {
		plugConfig["guard-url"] = env.GuardUrl
	}

	body := map[string][]string{
		"abc": {"ccc", "dddd"},
		"www": {"aaa", "bbb"},
	}
	jsonBytes, _ = json.Marshal(body)
	utils.MinimumInterval = 1 * time.Millisecond

	wg.Add(1) // Shutdown after one simulation ends
	for svc := 0; svc < NumServices; svc++ {
		sid := fmt.Sprintf("simulate-%x", svc)
		for ins := 0; ins < NumInstances; ins++ {
			plugConfig["guardian-load-interval"] = fmt.Sprintf("%dns", rand.Intn(10000000000))
			plugConfig["report-pile-interval"] = fmt.Sprintf("%dns", rand.Intn(100000000))
			plugConfig["pod-monitor-interval"] = fmt.Sprintf("%dns", rand.Intn(10000000000))
			fmt.Printf("plugConfig %v\n", plugConfig)
			g := guardgate.NewGate()
			g.Init(context.Background(), plugConfig, sid, "", pi.Log)
			defer g.Shutdown()
			for i := 0; i < 10; i++ {
				go simulate(g)
			}
		}
	}

	// wait for the first simulation to end
	wg.Wait()
}
