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
	"encoding/json"
	"reflect"
	"testing"
)

// Utility function to convert []interface{} to [][]interface{}
func toSlice(slices []interface{}) [][]interface{} {
	result := make([][]interface{}, len(slices))
	for sliceIndex := 0; sliceIndex < len(slices); sliceIndex++ {
		s := reflect.ValueOf(slices[sliceIndex])
		if s.Kind() != reflect.Slice {
			panic("InterfaceSlice() given a non-slice type")
		}

		// Keep the distinction between nil and empty slice input
		if s.IsNil() {
			return nil
		}

		converted := make([]interface{}, s.Len())

		for i := 0; i < s.Len(); i++ {
			converted[i] = s.Index(i).Interface()
		}
		result[sliceIndex] = converted
	}
	return result
}

func ValueTests_Test(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	args := toSlice(arguments)

	t.Run("Basics", func(t *testing.T) {

		// Initial Tests
		piles[9].Clear()
		piles[3].mergeI(piles[4])
		configs[5].learnI(piles[5])
		configs[6].decideI(profiles[0])
		piles[6].Clear()

		// Test ProfileValue
		for i, v := range args {
			profiles[i].profileI(v...)
		}

		// Test PileValue
		for i, profile := range profiles {
			piles[i].addI(profile)
			piles[i].Clear()
			piles[i].addI(profile)
			piles[i].addI(profile)
			piles[0].mergeI(piles[i])
			piles[0].mergeI(piles[i])
		}

		// Test ConfigValue
		for i, pile := range piles {
			configs[0].learnI(pile)
			configs[0].learnI(pile)

			if d := configs[0].decideI(profiles[i]); d != nil {
				t.Errorf("config.Decide(profile) wrong decision: %s\nFor profile %s\nwhen using config %s\n", d.String(""), profiles[i], configs[0])
			}
		}
	})
}

func ValueTests_Test_WithMarshal(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	profile := profiles[0]
	pile := piles[0]
	config := configs[0]
	args := toSlice(arguments)

	t.Run("Basics", func(t *testing.T) {

		// Test ProfileValue
		profile.profileI(args[0]...)

		// Test PileValue
		pile.addI(profile)
		pile.Clear()
		pile.addI(profile)
		pile.addI(profile)
		pile.mergeI(pile)
		pile.mergeI(pile)
		var err error
		var bytes []byte
		if bytes, err = json.Marshal(pile); err != nil {
			t.Errorf("json.Marshal Error %v", err.Error())
		}
		if err = json.Unmarshal(bytes, &pile); err != nil {
			t.Errorf("json.Unmarshal Error %v", err.Error())
			t.Errorf("bytes: %s", string(bytes))
		}
		// Test ConfigValue
		config.learnI(pile)
		config.learnI(pile)

		if d := config.decideI(profile); d != nil {
			t.Errorf(d.String("config.Decide(profile) wrong decission:"))
		}

		if bytes, err = json.Marshal(config); err != nil {
			t.Errorf("json.Marshal Error %v", err.Error())
		}
		if err = json.Unmarshal(bytes, &config); err != nil {
			t.Errorf("json.Unmarshal Error %v", err.Error())
			t.Errorf("bytes: %s", string(bytes))
		}
	})
}

func ValueTests_SimpleTest(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	pile := piles[0]
	config := configs[0]
	args := toSlice(arguments)
	t.Run("Basics", func(t *testing.T) {
		// Test ProfileValue
		for i, v := range args {
			profiles[i].profileI(v...)
		}

		// Test PileValue
		pile.addI(profiles[0])

		// test ConfigValue
		config.learnI(pile)
		if d := config.decideI(profiles[0]); d != nil {
			t.Errorf("config.Decide(profile) wrong decission: %s", d.String(""))
		}
		if d := config.decideI(profiles[1]); d == nil {
			t.Errorf("config.Decide(profile) expected a reject of %s after learning %s\n", args[1], args[0])
		}
		if d := config.decideI(profiles[2]); d == nil {
			t.Errorf("config.Decide(profile) expected a reject of %s after learning %s\n", args[2], args[0])
		}
	})
}

func ValueProfile_MarshalTest(t *testing.T, profiles []ValueProfile) {
	profileIn := profiles[0]
	profileOut := profiles[1]
	t.Run("Pile Marshal", func(t *testing.T) {

		var bytes []byte
		var err error
		if bytes, err = json.Marshal(profileIn); err != nil {
			t.Errorf("json.Marshal Error %v", err.Error())
		}
		if err = json.Unmarshal(bytes, &profileOut); err != nil {
			t.Errorf("json.Unmarshal Error %v", err.Error())
			t.Errorf("bytes: %s", string(bytes))
		}
	})
}

func ValuePile_MarshalTest(t *testing.T, piles []ValuePile) {
	pileIn := piles[0]
	pileOut := piles[1]
	t.Run("Pile Marshal", func(t *testing.T) {

		var bytes []byte
		var err error
		if bytes, err = json.Marshal(pileIn); err != nil {
			t.Errorf("json.Marshal Error %v", err.Error())
		}
		if err = json.Unmarshal(bytes, &pileOut); err != nil {
			t.Errorf("json.Unmarshal Error %v", err.Error())
			t.Errorf("bytes: %s", string(bytes))
		}
	})
}

func ValueConfig_MarshalTest(t *testing.T, configs []ValueConfig) {
	configIn := configs[0]
	configOut := configs[1]

	t.Run("Config Marshal", func(t *testing.T) {
		var bytes []byte
		var err error
		if bytes, err = json.Marshal(configIn); err != nil {
			t.Errorf("json.Marshal Error %v", err.Error())
		}
		if err = json.Unmarshal(bytes, &configOut); err != nil {
			t.Errorf("json.Unmarshal Error %v", err.Error())
			t.Errorf("bytes: %s", string(bytes))
		}
	})
}

func ValueTests_TestAdd(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	args := toSlice(arguments)
	t.Run("Basics", func(t *testing.T) {
		// Test ProfileValue
		profiles[0].profileI(args[0]...)
		profiles[1].profileI(args[1]...)

		// Test PileValue
		piles[0].addI(profiles[0])
		piles[0].addI(profiles[1])

		// test ConfigValue
		configs[0].learnI(piles[0])
		if d := configs[0].decideI(profiles[0]); d != nil {
			t.Errorf("config.Decide(profile) wrong decission: %s", d.String(""))
		}
		if d := configs[0].decideI(profiles[1]); d != nil {
			t.Errorf("config.Decide(profile) wrong decission: %s", d.String(""))
		}
	})
}

func ValueTests_TestMerge(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	args := toSlice(arguments)
	t.Run("Basics", func(t *testing.T) {

		// Test ProfileValue
		profiles[0].profileI(args[0]...)
		profiles[1].profileI(args[1]...)

		// Test PileValue
		piles[0].addI(profiles[0])
		piles[1].addI(profiles[1])
		piles[0].mergeI(piles[1])

		// test ConfigValue
		configs[0].learnI(piles[0])
		if d := configs[0].decideI(profiles[0]); d != nil {
			t.Errorf(d.String("config.Decide(profile) wrong decission: "))
		}
		if d := configs[0].decideI(profiles[1]); d != nil {
			t.Errorf(d.String("config.Decide(profile) wrong decission: "))
		}
	})
}

func ValueTests_TestFuse(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, arguments ...interface{}) {
	args := toSlice(arguments)
	t.Run("Basics", func(t *testing.T) {

		// Test ProfileValue
		profiles[0].profileI(args[0]...)
		profiles[1].profileI(args[1]...)

		// Test PileValue
		piles[0].addI(profiles[0])
		piles[1].addI(profiles[1])

		// test ConfigValue
		configs[0].learnI(piles[0])
		configs[0].learnI(piles[1])

		if d := configs[0].decideI(profiles[0]); d != nil {
			t.Errorf(d.String("config.Decide(profile) wrong decission: "))
		}
		if d := configs[0].decideI(profiles[1]); d != nil {
			t.Errorf(d.String("config.Decide(profile) wrong decission: "))
		}
	})
}

func ValueTests_All(t *testing.T, profiles []ValueProfile, piles []ValuePile, configs []ValueConfig, args ...interface{}) {
	ValueTests_SimpleTest(t, profiles, piles, configs, args...)
	ValueTests_Test(t, profiles, piles, configs, args...)
	ValueTests_TestAdd(t, profiles, piles, configs, args...)
	ValueTests_TestMerge(t, profiles, piles, configs, args...)
	ValueTests_TestFuse(t, profiles, piles, configs, args...)
	ValueConfig_MarshalTest(t, configs)
	ValuePile_MarshalTest(t, piles)
	ValueProfile_MarshalTest(t, profiles)
	ValueTests_Test_WithMarshal(t, profiles, piles, configs, args...)
}

func TestDecideInner(t *testing.T) {
	t.Run("Simple", func(t *testing.T) {
		var current *Decision
		var str, expected string

		DecideInner(&current, 7, "X")
		if current == nil {
			t.Error("Expected current to no longer be nil")
			return
		}
		if current.result != 7 {
			t.Error("Expected current.result to be 7")
			return
		}
		str = current.Summary()
		expected = "Fail (7)"
		if str != expected {
			t.Errorf("Expected current.Summary to be '%s' received '%s'", expected, str)
			return
		}
		str = current.String("Y")
		expected = "Y[X,]"
		if str != expected {
			t.Errorf("Expected string '%s' received '%s'", expected, str)
			return
		}
		DecideInner(&current, 3, "Z(%d)", 8)
		if current == nil {
			t.Error("Expected current to no longer be nil")
			return
		}
		if current.result != 10 {
			t.Error("Expected current.result to be 10")
			return
		}
		str = current.Summary()
		expected = "Fail (10)"
		if str != expected {
			t.Errorf("Expected current.Summary to be '%s' received '%s'", expected, str)
			return
		}
		str = current.String("Y")
		expected = "Y[X,Z(8),]"
		if str != expected {
			t.Errorf("Expected string '%s' received '%s'", expected, str)
			return
		}
	})

}

func TestDecideChild(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var current *Decision
		DecideChild(&current, nil, "X")
		if current != nil {
			t.Error("Expected current to be nil")
		}
	})

	t.Run("simple", func(t *testing.T) {
		var current, child *Decision
		var str, expected, alternative string

		childDecision := Decision{result: 4}

		DecideChild(&current, &childDecision, "X")
		if current == nil {
			t.Error("Expected current to no longer be nil")
			return
		}

		if current.result != 4 {
			t.Errorf("Expected current.result to be 4 instead received %d", current.result)
			return
		}
		str = current.Summary()
		expected = "Fail (4)"
		if str != expected {
			t.Errorf("Expected current.Summary to be '%s' received %s", expected, str)
			return
		}
		str = current.String("Y")
		expected = "Y[X:[],]"
		if str != expected {
			t.Errorf("Expected string '%s' received '%s'", expected, str)
			return
		}

		DecideChild(&current, &childDecision, "Z")
		if current.result != 8 {
			t.Errorf("Expected current.result to be 8 instead received %d", current.result)
			return
		}
		str = current.Summary()
		expected = "Fail (8)"
		if str != expected {
			t.Errorf("Expected current.Summary to be '%s' received '%s'", expected, str)
			return
		}
		str = current.String("Y")
		expected = "Y[X:[],Z:[],]"
		alternative = "Y[Z:[],X:[],]"
		if str != expected && str != alternative {
			t.Errorf("Expected string '%s' or '%s' received '%s'", expected, alternative, str)
			return
		}

		current = nil
		DecideChild(&child, &childDecision, "Z")
		DecideChild(&current, child, "X")
		if current == nil {
			t.Error("Expected current to no longer be nil")
			return
		}

		if current.result != 4 {
			t.Errorf("Expected current.result to be 4 instead received %d", current.result)
			return
		}
		str = current.Summary()
		expected = "Fail (4)"
		if str != expected {
			t.Errorf("Expected current.Summary to be '%s' received %s", expected, str)
			return
		}
		str = current.String("Y")
		expected = "Y[X:[Z:[],],]"
		if str != expected {
			t.Errorf("Expected string '%s' received '%s'", expected, str)
			return
		}
	})

}
