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

package guardutils

import (
	"fmt"
	"time"
)

var (
	MinimumInterval = 5 * time.Second
)

type Ticker struct {
	minimumInterval time.Duration
	interval        time.Duration
	ticker          *time.Ticker
}

func NewTicker(minimumInterval time.Duration) *Ticker {
	t := new(Ticker)
	t.minimumInterval = minimumInterval
	return t
}

func (t *Ticker) Parse(intervalStr string, defaultInterval time.Duration) error {
	var err error
	var d time.Duration

	t.interval = defaultInterval
	if intervalStr == "" {
		return nil
	}

	d, err = time.ParseDuration(intervalStr)
	if err != nil {
		return fmt.Errorf("interval illegal value %s - using default value instead (err: %v)", intervalStr, err)
	}
	t.interval = d
	return nil
}

func (t *Ticker) Start() {
	if t.interval < t.minimumInterval {
		t.interval = t.minimumInterval
	}
	t.ticker = time.NewTicker(t.interval)
}

func (t *Ticker) Stop() {
	if t.ticker != nil {
		t.ticker.Stop()
	}
}

func (t *Ticker) Ch() <-chan time.Time {
	if t.ticker == nil {
		t.ticker = time.NewTicker(t.minimumInterval)
		t.ticker.Stop()
	}
	return t.ticker.C
}
