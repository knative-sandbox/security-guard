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
	"sync"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	guardKubeMgr "knative.dev/security-guard/pkg/guard-kubemgr"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

var maxPileCount = uint32(1000)

// A cached record kept by guard-service for each deployed service
type serviceRecord struct {
	ns           string               // namespace of the deployed service
	sid          string               // name of the deployed service
	cmFlag       bool                 // indicate if the deployed service uses a ConfigMap (or CRD)
	guardianSpec *spec.GuardianSpec   // a copy of the cached deployed service Guardian (RO - no mutext needed)
	pile         spec.SessionDataPile // the deployed service Pile (RW - protected with pileMutex)
	pileMutex    sync.Mutex           // protect access to the pile
}

// service cache maintaining a cached record per deployed service
type services struct {
	kmgr       guardKubeMgr.KubeMgrInterface // KubeMgr to access KuebApi during cache misses
	mutex      sync.Mutex                    // protect access to cache map and to namespaces map
	cache      map[string]*serviceRecord     // the cache
	namespaces map[string]bool               // list of namespaces to watch for changes in ConfigMaps and CRDs
	tickerKeys []string                      // list of cache keys to periodically process during a tick()
}

// determine the cacheKey from its components
func serviceKey(ns string, sid string, cmFlag bool) string {
	service := sid + "." + ns
	if cmFlag {
		service += ".cm"
	}
	return service
}

func newServices() *services {
	s := new(services)
	s.cache = make(map[string]*serviceRecord, 64)
	s.namespaces = make(map[string]bool, 4)
	s.kmgr = guardKubeMgr.NewKubeMgr()
	return s
}

func (s *services) start() {
	// cant be tested due to KubeMgr
	s.kmgr.InitConfigs()
}

// Periodical background work to ensure small piles eventually are stored using KubeApi
func (s *services) tick() {
	// Tick should not include any asynchronous work
	// Move all asynchronous work (e.g. KubeApi work) to go routines
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(s.tickerKeys) == 0 {
		// Assign more work to be done now and in future ticks
		s.tickerKeys = make([]string, len(s.cache))
		i := 0
		for k := range s.cache {
			s.tickerKeys[i] = k
			i++
		}
	}

	// try up to 100 records per tick to find one that can be learned
	maxIterations := len(s.tickerKeys)
	if maxIterations > 100 {
		maxIterations = 100
	}

	// try to learn one record
	i := 0
	for ; i < maxIterations; i++ {
		if record, exists := s.cache[s.tickerKeys[i]]; exists {
			// we still have this record, lets learn it
			if s.learnPile(record) {
				// we learned one record
				i++
				break
			}
		}
	}

	// remove the keys we processed from the key slice
	s.tickerKeys = s.tickerKeys[i:]
}

// delete from cache
func (s *services) delete(ns string, sid string, cmFlag bool) {
	service := serviceKey(ns, sid, cmFlag)
	s.mutex.Lock()
	delete(s.cache, service)
	s.mutex.Unlock()
	pi.Log.Debugf("deleteSession %s", service)
}

// get from cache or from KubeApi (or get a default Guardian)
// if new namespace, start watching this namespace for changes in guardians
func (s *services) get(ns string, sid string, cmFlag bool) *serviceRecord {
	var knownNamespace bool = true

	service := serviceKey(ns, sid, cmFlag)

	s.mutex.Lock()
	// check if known Namespace
	_, knownNamespace = s.namespaces[ns]
	if !knownNamespace {
		s.namespaces[ns] = true
	}
	// try to get from cache
	record := s.cache[service]
	s.mutex.Unlock()

	// watch any unknown namespace
	if !knownNamespace {
		go s.kmgr.Watch(ns, cmFlag, s.update)
	}

	if record == nil {
		// not cached, get from kubeApi or create a default and add to cache
		record = s.set(ns, sid, cmFlag, s.kmgr.GetGuardian(ns, sid, cmFlag, true))
	}
	// record is never nil here

	return record
}

// set to cache
// caller ensures that guardianSpec is never nil
func (s *services) set(ns string, sid string, cmFlag bool, guardianSpec *spec.GuardianSpec) *serviceRecord {
	service := serviceKey(ns, sid, cmFlag)

	s.mutex.Lock()
	record, exists := s.cache[service]
	if !exists {
		record = new(serviceRecord)
		record.pile.Clear()
		record.ns = ns
		record.sid = sid
		record.cmFlag = cmFlag
		s.cache[service] = record
	}
	s.mutex.Unlock()

	record.guardianSpec = guardianSpec
	pi.Log.Debugf("cache record for %s.%s", ns, sid)
	return record
}

// update cache
// delete if guardianSpec is nil, set otherwise
func (s *services) update(ns string, sid string, cmFlag bool, guardianSpec *spec.GuardianSpec) {
	if guardianSpec == nil {
		s.delete(ns, sid, cmFlag)
	} else {
		s.set(ns, sid, cmFlag, guardianSpec)
	}
}

// update the record pile by merging a new pile
func (s *services) merge(record *serviceRecord, pile *spec.SessionDataPile) {
	record.pileMutex.Lock()
	record.pile.Merge(pile)
	record.pileMutex.Unlock()
	if record.pile.Count > maxPileCount {
		s.learnPile(record)
	}
}

// update the record guardianSpec by learning a new config and fusing with the record existing config
// update KubeAPI as well.
// return true if we try to learn and access kubeApi, false if count is zero and we have nothing to do
func (s *services) learnPile(record *serviceRecord) bool {
	if record.pile.Count == 0 {
		return false
	}
	config := new(spec.SessionDataConfig)

	record.pileMutex.Lock()
	config.Learn(&record.pile)
	record.pile.Clear()
	record.pileMutex.Unlock()

	if record.guardianSpec.Learned != nil {
		config.Fuse(record.guardianSpec.Learned)
	}

	// update the cached record
	record.guardianSpec.Learned = config
	record.guardianSpec.Learned.Active = true

	// update the kubeApi record
	go s.persist(record)

	return true
}

func (s *services) persist(record *serviceRecord) {
	if err := s.kmgr.Set(record.ns, record.sid, record.cmFlag, record.guardianSpec); err != nil {
		pi.Log.Infof("Failed to update KubeApi with new config %s.%s: %v", record.ns, record.sid, err)
	} else {
		pi.Log.Debugf("Update KubeApi with new config %s.%s", record.ns, record.sid)
	}
}
