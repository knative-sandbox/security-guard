/*
Copyright 2022 The Knative Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language gov erning permissions and
limitations under the License.
*/

package guardutils

import "testing"

func TestStat_Log(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "simple",
			want: "map[boom:1 x:4]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(Stat)
			s.Init()
			s.Add("x")
			s.Add("x")
			s.Add("boom")
			s.Add("x")
			s.Add("x")

			if got := s.Log(); got != tt.want {
				t.Errorf("Stat.Log() = %v, want %v", got, tt.want)
			}
		})
	}
}
