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

package v1alpha1

import (
	"testing"
)

func TestLimit_V1(t *testing.T) {
	arguments := [][]uint{
		{4},
		{5},
		{9},
		{254},
		{255},
		{0},
	}
	var args []interface{}
	var profiles []ValueProfile
	var piles []ValuePile
	var configs []ValueConfig
	for i := 0; i < 10; i++ {
		profiles = append(profiles, new(LimitProfile))
		piles = append(piles, new(LimitPile))
		configs = append(configs, new(LimitConfig))
	}
	for i := 0; i < len(arguments); i++ {
		args = append(args, arguments[i])
	}

	ValueTests_All(t, profiles, piles, configs, args...)
}
