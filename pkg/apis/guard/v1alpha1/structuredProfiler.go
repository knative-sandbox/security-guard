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
	"fmt"
	"reflect"
)

const (
	KindEmpty   = ""
	KindObject  = "object"
	KindArray   = "array"
	KindNumber  = "number"
	KindBoolean = "boolean"
	KindString  = "string"
	KindMulti   = "multi"
)

//////////////////// StructuredProfile ////////////////

// Exposes ValueProfile interface
//
//	 JsonProfile struct - maintain the profile of a json with some structure
//		Data Types: The default Golang data types for decoding and encoding JSON are as follows:
//			bool for JSON booleans.
//			float64 for JSON numbers.
//			string for JSON strings.
//			nil for JSON null.
//			array as JSON array.
//			map or struct as JSON Object.
type StructuredProfile struct {
	Kind string                        `json:"kind"` // bool, float64, string, array, map
	Vals []SimpleValProfile            `json:"vals"` // used for: array, boolean, number, string items
	Kv   map[string]*StructuredProfile `json:"kv"`   // used for: object items
}

// Profile a generic json
// Limited array support - data in arrays is stringified and analyzed with SimpleVal
// Implementation supports only array of strings
func (profile *StructuredProfile) profileI(args ...interface{}) {
	profile.Profile(args[0])
}

func (profile *StructuredProfile) Profile(data interface{}) {
	if data == nil {
		return
	}
	rData := reflect.ValueOf(data)
	switch rData.Kind() {
	case reflect.Slice:
		profile.Kind = KindArray
		profile.Vals = make([]SimpleValProfile, rData.Len())
		for i := 0; i < rData.Len(); i++ {
			val := rData.Index(i)
			// All arrays are treated as array of SimpleVals
			switch val.Kind() {
			case reflect.Map, reflect.Slice, reflect.Float64, reflect.Bool, reflect.String:
				profile.Vals[i].Profile(fmt.Sprint(val))
			default:
				panic(fmt.Sprintf("StructuredProfile.Profile() unknown Kind in Array: %v", val.Kind()))
			}
		}
	case reflect.Map:
		profile.Kind = KindObject
		profile.Kv = make(map[string]*StructuredProfile, rData.Len())
		for _, key := range rData.MapKeys() {
			k := key.String()
			v := rData.MapIndex(key)
			profile.Kv[k] = new(StructuredProfile)
			profile.Kv[k].Profile(v.Interface())
		}
	case reflect.Float64:
		profile.Kind = KindNumber
		profile.Vals = make([]SimpleValProfile, 1)
		profile.Vals[0].Profile(fmt.Sprintf("%f", data.(float64)))
	case reflect.Bool:
		profile.Kind = KindBoolean
		profile.Vals = make([]SimpleValProfile, 1)
		profile.Vals[0].Profile(fmt.Sprintf("%t", data.(bool)))
	case reflect.String:
		profile.Kind = KindString
		profile.Vals = make([]SimpleValProfile, 1)
		profile.Vals[0].Profile(data.(string))
	default:
		// Support json kinds only
		panic(fmt.Sprintf("StructuredProfile.Profile() unsupported Kind: %v", rData.Kind()))
	}
}

//////////////////// StructuredPile ////////////////

// Exposes ValuePile interface
type StructuredPile struct {
	Kind string                     `json:"kind"` // bool, float64, string, array, map
	Val  *SimpleValPile             `json:"val"`  // used for: array, boolean, number, string items
	Kv   map[string]*StructuredPile `json:"kv"`   // used for: object items
}

func (pile *StructuredPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*StructuredProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *StructuredPile) Add(profile *StructuredProfile) {
	if pile.Kind == KindEmpty {
		switch profile.Kind {
		case KindObject:
			pile.Kind = profile.Kind
			pile.Kv = make(map[string]*StructuredPile, len(profile.Kv))
		case KindArray, KindBoolean, KindNumber, KindString:
			pile.Kind = profile.Kind
			pile.Val = new(SimpleValPile)
		case KindEmpty:
			// nothing to do
			return
		case KindMulti:
			// we will set to multi if we are not already multi
		default:
			panic(fmt.Sprintf("StructuredProfile.Pile() unknown Kind: %v", profile.Kind))
		}
	}

	if pile.Kind != profile.Kind {
		pile.Kind = KindMulti
		return
	}
	switch profile.Kind {
	case KindObject:
		for k, v := range profile.Kv {
			vPile, exists := pile.Kv[k]
			if !exists {
				vPile = new(StructuredPile)
				pile.Kv[k] = vPile
			}
			vPile.Add(v)
		}
	case KindArray:
		for _, v := range profile.Vals {
			pile.Val.Add(&v)
		}
	case KindBoolean, KindNumber, KindString:
		pile.Val.Add(&profile.Vals[0])
	}
}

func (pile *StructuredPile) Clear() {
	pile.Kind = KindEmpty
	pile.Val = nil
	pile.Kv = nil
}

func (pile *StructuredPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*StructuredPile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *StructuredPile) Merge(otherPile *StructuredPile) {
	if pile.Kind == KindEmpty {
		pile.Kind = otherPile.Kind
		switch otherPile.Kind {
		case KindObject:
			pile.Kv = make(map[string]*StructuredPile, len(otherPile.Kv))
		case KindArray, KindBoolean, KindNumber, KindString:
			pile.Val = new(SimpleValPile)
		}
	}
	if pile.Kind != otherPile.Kind {
		pile.Kind = KindMulti
		return
	}
	switch otherPile.Kind {
	case KindObject:
		for k, v := range otherPile.Kv {
			vPile, exists := pile.Kv[k]
			if !exists {
				vPile = new(StructuredPile)
				pile.Kv[k] = vPile
			} else {
				vPile.Merge(v)
			}
		}
	case KindArray, KindBoolean, KindNumber, KindString:
		pile.Val.Merge(otherPile.Val)
	}
}

//////////////////// StructuredConfig ////////////////

// Exposes ValueConfig interface
type StructuredConfig struct {
	Kind string                       `json:"kind"` // boolean, number, string, skip, array, object
	Val  *SimpleValConfig             `json:"val"`  // used for: array, boolean, number, string items
	Kv   map[string]*StructuredConfig `json:"kv"`   // used for: object items
}

func (config *StructuredConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*StructuredProfile))
}

func (config *StructuredConfig) Decide(profile *StructuredProfile) *Decision {
	var current *Decision

	if config.Kind != profile.Kind {
		if config.Kind == KindMulti {
			return nil
		} else {
			DecideInner(&current, 1, "Structured -  kind mismatch allowed %s has %s", config.Kind, profile.Kind)
			return current
		}
	}
	switch config.Kind {
	case KindObject:
		for jpk, jpv := range profile.Kv {
			if config.Kv[jpk] == nil {
				DecideInner(&current, 1, "Structured - key not allowed: %s", jpk)
			} else {
				DecideChild(&current, config.Kv[jpk].Decide(jpv), "Structured - Key: %s", jpk)
			}
		}
	case KindArray:
		for _, jpv := range profile.Vals {
			DecideChild(&current, config.Val.Decide(&jpv), "Structured - array val")
		}
	case KindBoolean, KindNumber, KindString:
		DecideChild(&current, config.Val.Decide(&profile.Vals[0]), "Structured - val")
	}
	return current
}

func (config *StructuredConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*StructuredPile))
}

// pile is RO and unchanged - never uses pile internal objects
func (config *StructuredConfig) Learn(pile *StructuredPile) {
	if config.Kind == KindEmpty {
		config.Kind = pile.Kind
		switch pile.Kind {
		case KindObject:
			config.Kv = make(map[string]*StructuredConfig, len(pile.Kv))
			config.Val = nil
		case KindArray, KindBoolean, KindNumber, KindString:
			config.Val = new(SimpleValConfig)
			config.Kv = nil
		}
	}
	if config.Kind != pile.Kind {
		config.Kind = KindMulti
		return
	}
	switch config.Kind {
	case KindObject:
		for k, v := range pile.Kv {
			vConfig, exists := config.Kv[k]
			if !exists {
				vConfig = new(StructuredConfig)
				config.Kv[k] = vConfig
			}
			vConfig.Learn(v)
		}
	case KindArray, KindBoolean, KindNumber, KindString:
		config.Val.Learn(pile.Val)
	}
}

func (config *StructuredConfig) Prepare() {
	switch config.Kind {
	case KindObject:
		for _, v := range config.Kv {
			v.Prepare()
		}
	case KindArray, KindBoolean, KindNumber, KindString:
		config.Val.Prepare()
	}
}
