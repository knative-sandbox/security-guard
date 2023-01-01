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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	utils "knative.dev/security-guard/pkg/guard-utils"
)

func addToPile(s *services) {
	profile1 := &spec.SessionDataProfile{}
	profile1.Req.Method.ProfileString("Get")
	pile1 := spec.SessionDataPile{}
	pile1.Add(profile1)
	r1 := s.get("ns", "sid1", false)
	s.merge(r1, &pile1)
}

func Test_learner_mainEventLoop(t *testing.T) {
	quit := make(chan string)

	// services
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	learnTicker := utils.NewTicker(100000)
	learnTicker.Parse("", 100000)
	learnTicker.Start()

	statTicker := utils.NewTicker(100000)
	statTicker.Parse("", 100000)
	statTicker.Start()

	addToPile(s)

	t.Run("simple", func(t *testing.T) {
		l := &learner{
			services:        s,
			pileLearnTicker: learnTicker,
			statTicker:      statTicker,
		}
		if s.cache["sid1.ns"].pile.Count != 1 {
			t.Errorf("Expected 1 in pile  have %d", s.cache["sid1.ns"].pile.Count)
		}

		// Start event loop
		go l.mainEventLoop(quit)

		<-time.After(100 * time.Millisecond)

		if s.cache["sid1.ns"].pile.Count != 0 {
			t.Errorf("Expected 0 in pile  have %d", s.cache["sid1.ns"].pile.Count)
		}
		quit <- "test done"
		// Asked event loop to quit
		<-time.After(100 * time.Millisecond)

		addToPile(s)
		if s.cache["sid1.ns"].pile.Count != 1 {
			t.Errorf("Expected 1 in pile  have %d", s.cache["sid1.ns"].pile.Count)
		}

		<-time.After(100 * time.Millisecond)

		if s.cache["sid1.ns"].pile.Count != 1 {
			t.Errorf("Expected 1 in pile  have %d", s.cache["sid1.ns"].pile.Count)
		}
	})

}

func Test_learner_baseHandler(t *testing.T) {
	tests := []struct {
		name       string
		query      url.Values
		wantErr    bool
		wantSid    string
		wantNs     string
		wantCmFlag bool
	}{
		{
			name:    "doubleCm",
			query:   url.Values{"ns": []string{"myns"}, "sid": []string{"x"}, "cm": []string{"x", "y"}},
			wantErr: true,
		},
		{
			name:    "ok",
			query:   url.Values{"ns": []string{"myns"}, "sid": []string{"x"}},
			wantSid: "x",
			wantNs:  "myns",
		},
		{
			name:    "okWithBadCm",
			query:   url.Values{"ns": []string{"myns"}, "sid": []string{"x"}, "cm": []string{"x"}},
			wantSid: "x",
			wantNs:  "myns",
		},
		{
			name:       "okWithTrueCm",
			query:      url.Values{"ns": []string{"myns"}, "sid": []string{"x"}, "cm": []string{"true"}},
			wantSid:    "x",
			wantNs:     "myns",
			wantCmFlag: true,
		},
		{
			name:    "okWithFalseCm",
			query:   url.Values{"ns": []string{"myns"}, "sid": []string{"x"}, "cm": []string{"false"}},
			wantSid: "x",
			wantNs:  "myns",
		},
	}
	for _, tt := range tests {
		// services
		s := new(services)
		s.cache = make(map[string]*serviceRecord, 64)
		s.namespaces = make(map[string]bool, 4)
		s.kmgr = new(fakeKmgr)

		ticker := utils.NewTicker(100000)
		t.Run(tt.name, func(t *testing.T) {
			l := &learner{
				services:        s,
				pileLearnTicker: ticker,
			}
			gotCmFlag, gotSid, gotNs, gotErr := l.queryData(tt.query)
			if tt.wantErr == (gotErr == nil) {
				t.Errorf("learner.queryData() gotErr = %v, want %v", gotErr, tt.wantErr)
			}
			if tt.wantCmFlag != gotCmFlag {
				t.Errorf("learner.queryData() wantCmFlag = %v, and gotCmFlag %v", tt.wantCmFlag, gotCmFlag)
			}
			if tt.wantSid != gotSid {
				t.Errorf("learner.queryData() wantSid = %v, and gotSid %v", tt.wantSid, gotSid)
			}
			if tt.wantNs != gotNs {
				t.Errorf("learner.queryData() wantNs = %v, and gotNs %v", tt.wantNs, gotNs)
			}
		})
	}
}

func TestFetchConfigHandler_NoToken(t *testing.T) {
	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/config?sid=mysid&ns=myns", nil)
	if err != nil {
		t.Fatal(err)
	}

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(mylearner.fetchConfig)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}

	// Check the response body is what we expect.
	buf := make([]byte, 0)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}

}

func TestFetchConfigHandler_main(t *testing.T) {
	os.Unsetenv("GUARD_SERVICE_PORT")

	if target != ":8888" {
		t.Errorf("handler returned wrong default target code: got %s want %s", target, ":8888")
	}
}

func TestFetchConfigHandler_POST(t *testing.T) {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	ticker := utils.NewTicker(100000)
	l := &learner{
		services:        s,
		pileLearnTicker: ticker,
	}

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/config?sid=mysid&ns=myns", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer abc")
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(l.fetchConfig)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusNotFound {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusNotFound)
	}

	// Check the response body is what we expect.
	buf := make([]byte, 0)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}
}

func TestFetchConfigHandler_WithQuery(t *testing.T) {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	ticker := utils.NewTicker(100000)
	l := &learner{
		services:        s,
		pileLearnTicker: ticker,
	}

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("GET", "/config?sid=x&ns=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer abc")
	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(l.fetchConfig)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	//expected := `{"configured": null,"control":null}`
	g := new(spec.GuardianSpec)
	buf, _ := json.Marshal(g)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}
}

func TestProcessPileHandler_NoQuery(t *testing.T) {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	ticker := utils.NewTicker(100000)
	l := &learner{
		services:        s,
		pileLearnTicker: ticker,
	}

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/pile?sid=mysid&ns=myns", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer abc")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(l.processPile)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	// Check the response body is what we expect.
	buf := make([]byte, 0)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}
}

func TestProcessPileHandler_WithQueryAndPile(t *testing.T) {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	ticker := utils.NewTicker(100000)
	l := &learner{
		services:        s,
		pileLearnTicker: ticker,
	}
	record := s.get("ns", "sid9", false)
	postBody, _ := json.Marshal(&record.pile)
	reqBody := bytes.NewBuffer(postBody)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/pile?sid=x&ns=x", reqBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer abc")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(l.processPile)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body is what we expect.
	//expected := `{"configured": null,"control":null}`
	g := new(spec.GuardianSpec)
	buf, _ := json.Marshal(g)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}
}

func TestProcessPileHandler_WithQueryAndNoPile(t *testing.T) {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)

	ticker := utils.NewTicker(100000)
	l := &learner{
		services:        s,
		pileLearnTicker: ticker,
	}
	postBody, _ := json.Marshal("xx")
	reqBody := bytes.NewBuffer(postBody)

	// Create a request to pass to our handler. We don't have any query parameters for now, so we'll
	// pass 'nil' as the third parameter.
	req, err := http.NewRequest("POST", "/pile?sid=x&ns=x", reqBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Authorization", "Bearer abc")

	// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(l.processPile)

	// Our handlers satisfy http.Handler, so we can call their ServeHTTP method
	// directly and pass in our Request and ResponseRecorder.
	handler.ServeHTTP(rr, req)

	// Check the status code is what we expect.
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusBadRequest)
	}

	// Check the response body is what we expect.
	buf := make([]byte, 0)
	if reflect.DeepEqual(rr.Body, buf) {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), buf)
	}
}

var target string
var mylearner *learner

func init() {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = new(fakeKmgr)
	mylearner, _, target, _ = preMain(100000)
	mylearner.services = s

	env.GuardServiceAuth = true
}
