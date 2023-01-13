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

package guardkubemgr

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	pi "knative.dev/security-guard/pkg/pluginterfaces"
)

// Watch never returns - use with a goroutine
// Watch for changes in Guardian CRDs and Guardian ConfigMaps
// No matter how we get an update, cmFlag is used when calling set() as this is what the guard-gate is configured for!
func (k *KubeMgr) Watch(ns string, cmFlag bool, set func(ns string, sid string, cmFlag bool, g *spec.GuardianSpec)) {
	// Skip during simulations
	if len(ns) == 0 {
		return
	}

	for {
		k.WatchOnce(ns, cmFlag, set)
		timeout, _ := time.ParseDuration("100s")
		time.Sleep(timeout)
	}
}

// Watch for changes in Guardian CRDs and Guardian ConfigMaps
// No matter how we get an update, cmFlag is used when calling set() as this is what the guard-gate is configured for!
func (k *KubeMgr) WatchOnce(ns string, cmFlag bool, set func(ns string, sid string, cmFlag bool, g *spec.GuardianSpec)) (e error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			e = fmt.Errorf("recovered from panic while watching cm and crd for ns %s! recover: %v", ns, recovered)
		}
	}()
	watcherCrd, err := k.crdClient.Guardians(ns).Watch(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch crd ns %s err %v", ns, err)
	}
	chCrd := watcherCrd.ResultChan()
	watcherCm, err := k.cmClient.CoreV1().ConfigMaps(ns).Watch(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("watch cm ns %s err %v", ns, err)
	}
	chCm := watcherCm.ResultChan()
	for {
		select {
		case event, ok := <-chCrd:
			if !ok {
				// the channel got closed, so we need to restart
				return fmt.Errorf("watch crd ns %s kubernetes hung up on us, restarting event watcher", ns)
			}

			// handle the crd event
			switch event.Type {
			case watch.Deleted:
				fallthrough
			case watch.Modified:
				fallthrough
			case watch.Added:
				g, ok := event.Object.(*spec.Guardian)
				if !ok {
					pi.Log.Infof("kubernetes cant convert to type Guardian\n")
					return
				}
				ns := g.ObjectMeta.Namespace
				sid := g.ObjectMeta.Name

				if event.Type == watch.Deleted {
					set(ns, sid, cmFlag, nil)
					continue
				}
				set(ns, sid, cmFlag, g.Spec)
			case watch.Error:
				s := event.Object.(*metav1.Status)
				pi.Log.Infof("Error during watch CRD: \n\tListMeta %v\n\tTypeMeta %v\n", s.ListMeta, s.TypeMeta)
			}
		case event, ok := <-chCm:
			if !ok {
				// the channel got closed, so we need to restart
				return fmt.Errorf("watch cm ns %s kubernetes hung up on us, restarting event watcher", ns)
			}

			// handle the cm event
			switch event.Type {
			case watch.Deleted:
				fallthrough
			case watch.Modified:
				fallthrough
			case watch.Added:
				cm, ok := event.Object.(*corev1.ConfigMap)
				if !ok {
					return fmt.Errorf("watch cm ns %s kubernetes cant convert to type configmap", ns)
				}
				ns := cm.ObjectMeta.Namespace
				sid := cm.ObjectMeta.Name
				if !strings.HasPrefix(sid, "guardian.") || strings.HasPrefix(sid, "guardian.ns.") {
					// skip...
					continue
				}
				if event.Type == watch.Deleted {
					set(ns, sid, cmFlag, nil)
					continue
				}
				if cm.Data["Guardian"] == "" {
					set(ns, sid, cmFlag, nil)
					continue
				}
				g := new(spec.GuardianSpec)
				gdata := []byte(cm.Data["Guardian"])
				jsonErr := json.Unmarshal(gdata, g)
				if jsonErr != nil {
					pi.Log.Infof("wsgate getConfig sid=%s, ns=%s: unmarshel error %v\n", sid, ns, jsonErr)
					set(ns, sid, cmFlag, nil)
					continue
				}
				set(ns, sid, cmFlag, g)
			case watch.Error:
				s := event.Object.(*metav1.Status)
				pi.Log.Infof("Error during watch CM: \n\tListMeta %v\n\tTypeMeta %v\n", s.ListMeta, s.TypeMeta)
			}
		case <-time.After(10 * time.Minute):
			// deal with the issue where we get no events
			return fmt.Errorf("watch cm ns %s timeout, restarting event watcher", ns)
		}
	}
}
