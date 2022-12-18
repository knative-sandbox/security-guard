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

//////////////////// SetProfile ////////////////

// Exposes ValueProfile interface
// A Slice of tokens
type SetProfile []string

func (profile *SetProfile) profileI(args ...interface{}) {
	switch v := args[0].(type) {
	case string:
		profile.ProfileString(v)
	case []string:
		profile.ProfileStringSlice(v)
	default:
		panic("Unsupported type in SetProfile")
	}
}

func (profile *SetProfile) ProfileString(str string) {
	*profile = []string{str}
}

func (profile *SetProfile) ProfileStringSlice(strSlice []string) {
	*profile = make(SetProfile, len(strSlice))
	copy(*profile, strSlice)
}

//////////////////// SetPile ////////////////

// Exposes ValuePile interface
// During json.Marshal(), SetPile exposes only the List
// After json.Unmarshal(), the map will be nil even when the List is not empty
// If the map is nil, it should be populated from the information in List
// If the map is populated it is always kept in-sync with the information in List
type SetPile struct {
	List []string `json:"set"`
	m    map[string]bool
}

func (pile *SetPile) addI(valProfile ValueProfile) {
	pile.Add(valProfile.(*SetProfile))
}

// profile is RO and unchanged - never uses profile internal objects
func (pile *SetPile) Add(profile *SetProfile) {
	if *profile == nil {
		return
	}
	if pile.m == nil {
		pile.m = make(map[string]bool, len(pile.List)+len(*profile))
		// Populate the map from the information in List
		for _, v := range pile.List {
			pile.m[v] = true
		}
	}
	for _, v := range *profile {
		if !pile.m[v] {
			pile.m[v] = true
			pile.List = append(pile.List, v)
		}
	}
}

func (pile *SetPile) Clear() {
	pile.m = nil
	pile.List = nil
}

func (pile *SetPile) mergeI(otherValPile ValuePile) {
	pile.Merge(otherValPile.(*SetPile))
}

// otherPile is RO and unchanged - never uses otherPile internal objects
func (pile *SetPile) Merge(otherPile *SetPile) {
	if pile.m == nil {
		pile.m = make(map[string]bool, len(pile.List)+len(otherPile.List))
		// Populate the map from the information in List
		for _, v := range pile.List {
			pile.m[v] = true
		}
	}
	for _, v := range otherPile.List {
		if !pile.m[v] {
			pile.m[v] = true
			pile.List = append(pile.List, v)
		}
	}
}

//////////////////// SetConfig ////////////////

// Exposes ValueConfig interface
// During json.Marshal(), SetConfig exposes only the List
// After json.Unmarshal(), the map will be nil even when the List is not empty
// If the map is nil, it should be populated from the information in List
// If the map is populated it is always kept in-sync with the information in List
type SetConfig struct {
	List []string `json:"set"`
	m    map[string]bool
}

func (config *SetConfig) decideI(valProfile ValueProfile) *Decision {
	return config.Decide(valProfile.(*SetProfile))
}

func (config *SetConfig) Decide(profile *SetProfile) *Decision {
	var current *Decision

	if *profile == nil {
		return nil
	}

	for _, v := range *profile {
		if !config.m[v] {
			DecideInner(&current, 1, "Unexpected key %s in Set", v)
		}
	}

	return current
}

func (config *SetConfig) learnI(valPile ValuePile) {
	config.Learn(valPile.(*SetPile))
}

// pile is RO and unchanged - never uses pile internal objects
func (config *SetConfig) Learn(pile *SetPile) {
	config.List = make([]string, len(pile.List))
	config.m = make(map[string]bool, len(pile.List))

	for i, v := range pile.List {
		config.m[v] = true
		config.List[i] = v
	}
}

func (config *SetConfig) fuseI(otherValConfig ValueConfig) {
	config.Fuse(otherValConfig.(*SetConfig))
}

// otherConfig is RO and unchanged - never uses otherConfig internal objects
func (config *SetConfig) Fuse(otherConfig *SetConfig) {
	if config.m == nil {
		config.m = make(map[string]bool, len(config.List)+len(otherConfig.List))
		// Populate the map from the information in List
		for _, v := range config.List {
			config.m[v] = true
		}
	}
	for _, v := range otherConfig.List {
		if !config.m[v] {
			config.m[v] = true
			config.List = append(config.List, v)
		}
	}
}

func (config *SetConfig) Prepare() {
	config.m = make(map[string]bool, len(config.List))
	// Populate the map from the information in List
	for _, v := range config.List {
		config.m[v] = true
	}
}
