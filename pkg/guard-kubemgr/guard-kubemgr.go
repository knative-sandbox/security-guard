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
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	guardianclientset "knative.dev/security-guard/pkg/client/clientset/versioned"
	guardv1alpha1 "knative.dev/security-guard/pkg/client/clientset/versioned/typed/guard/v1alpha1"
	pi "knative.dev/security-guard/pkg/pluginterfaces"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// This package stores and controls Guardians via KubeApi
// Guardians are composed of a set of micro-rules to control a guard-gate
// Guardians are stored either as a CRD or in a ConfigMap depending on the system used

type KubeMgrInterface interface {
	InitConfigs()
	Read(ns string, sid string, isCm bool) (*spec.GuardianSpec, error)
	Create(ns string, sid string, isCm bool, guardianSpec *spec.GuardianSpec) error
	Set(ns string, sid string, isCm bool, guardianSpec *spec.GuardianSpec) error
	GetGuardian(ns string, sid string, cm bool, autoActivate bool) *spec.GuardianSpec
	Watch(ns string, cmFlag bool, set func(ns string, sid string, cmFlag bool, g *spec.GuardianSpec))
	TokenData(token string, labels []string) (sid string, ns string, err error)
}

// KubeMgr manages Guardian CRDs and Guardian CMs
type KubeMgr struct {
	// Function for returning k8s config
	getConfigFunc func() (*rest.Config, error)

	// Kubernetes client for Config Maps
	cmClient kubernetes.Interface

	// CRD client for Guardian CRD
	crdClient guardv1alpha1.GuardV1alpha1Interface
}

func NewKubeMgr() KubeMgrInterface {
	k := new(KubeMgr)
	k.getConfigFunc = rest.InClusterConfig
	return k
}

func (k *KubeMgr) getConfigs() *rest.Config {
	var err error
	var kubeCfg *rest.Config
	var devKubeConfigStr *string

	// Try to detect in-cluster config
	if kubeCfg, err = k.getConfigFunc(); err == nil {
		return kubeCfg
	}

	// Not running in cluster
	if home := homedir.HomeDir(); home != "" {
		devKubeConfigStr = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		devKubeConfigStr = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// Use the current context in kubeconfig
	if kubeCfg, err = clientcmd.BuildConfigFromFlags("", *devKubeConfigStr); err != nil {
		panic(fmt.Sprintf("No Config found! err %s", err.Error()))
	}
	return kubeCfg
}

// Initialize the Kubernetes client and CRD client to communicate with the KubeApi
func (k *KubeMgr) InitConfigs() {
	var err error

	kubeCfg := k.getConfigs()

	// Create a cm client
	k.cmClient, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		panic(err.Error())
	}

	// Create a crd client
	crdClientSet, err := guardianclientset.NewForConfig(kubeCfg)
	if err != nil {
		panic(err.Error())
	}
	k.crdClient = crdClientSet.GuardV1alpha1()
}

// readCrd - Reads a Guardian Crd from KubeApi
// Returns a Guardian
// Returns error if can't read a Guardian from a well structured Crd
func (k *KubeMgr) readCrd(ns string, sid string) (*spec.GuardianSpec, error) {
	g, err := k.crdClient.Guardians(ns).Get(context.TODO(), sid, metav1.GetOptions{})
	if err != nil {
		// can't read CRD
		return nil, fmt.Errorf("guardian crd %s.%s read error %w", sid, ns, err)
	}

	return g.Spec, nil
}

// readCm - Reads a Guardian ConfigMap from KubeApi
// Returns a Guardian
// Returns error if can't read a Guardian from a well structured ConfigMap
func (k *KubeMgr) readCm(ns string, sid string) (*spec.GuardianSpec, error) {
	cmName := "guardian." + sid

	cm, err := k.cmClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{})
	if err != nil {
		// can't read ConfigMap
		return nil, fmt.Errorf("guardian configmap %s read error %w", cmName, err)
	}

	gData, ok := cm.Data["Guardian"]
	if !ok || len(gData) == 0 {
		// malformed ConfigMap
		return nil, fmt.Errorf("guardian configmap %s malformed", cmName)
	}

	g := new(spec.GuardianSpec)
	if err := json.Unmarshal([]byte(gData), g); err != nil {
		// corrupted ConfigMap
		return nil, fmt.Errorf("guardian configmap %s unmarshal error %w", cmName, err)
	}

	return g, nil
}

// Read - Reads a Guardian ConfigMap or CRD from KubeApi
// Returns a Guardian
// Returns error if can't read a well structured Guardian
func (k *KubeMgr) Read(ns string, sid string, isCm bool) (*spec.GuardianSpec, error) {
	// Skip during simulations
	if len(ns) == 0 {
		return nil, nil
	}

	if isCm {
		return k.readCm(ns, sid)
	} else {
		return k.readCrd(ns, sid)
	}
}

// createCm - Create a new Guardian Config Map
// Uses delete and create sequence
// In rare cases, the ConfigMap may be created by another entity after the delete and before the create which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose of guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) createCm(ns string, sid string, guardianSpec *spec.GuardianSpec) error {
	var gBytes []byte
	var err error
	var cm *corev1.ConfigMap
	cmName := "guardian." + sid

	// first, try to delete
	k.cmClient.CoreV1().ConfigMaps(ns).Delete(context.TODO(), cmName, metav1.DeleteOptions{})

	// Now create
	cm = new(corev1.ConfigMap)
	cm.Name = cmName
	cm.Data = make(map[string]string, 1)

	if gBytes, err = json.Marshal(guardianSpec); err != nil {
		return fmt.Errorf("create configmap %s: marshaling error %w", cmName, err)
	}

	cm.Data["Guardian"] = string(gBytes)

	if _, err = k.cmClient.CoreV1().ConfigMaps(ns).Create(context.TODO(), cm, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create configmap %s: error creating resource: %w", cmName, err)
	}
	return nil
}

// createCrd - Create a new Guardian CRD
// Uses delete and create sequence
// In rare cases, the CRD may be created by another entity after the delete and before the create which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) createCrd(ns string, sid string, guardianSpec *spec.GuardianSpec) error {
	var g *spec.Guardian
	var err error

	// first, try to delete
	k.crdClient.Guardians(ns).Delete(context.TODO(), sid, metav1.DeleteOptions{})

	// Now create
	g = new(spec.Guardian)
	g.Name = sid
	g.Spec = guardianSpec

	if _, err = k.crdClient.Guardians(ns).Create(context.TODO(), g, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("set crd: error creating resource: %w", err)
	}
	return nil
}

// Create - Create a new Guardian resource (ConfigMap or CRD)
// Uses delete and create sequence
// In rare cases, the resource may be created by another entity after the delete and before the create which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) Create(ns string, sid string, isCm bool, guardianSpec *spec.GuardianSpec) error {
	// Skip during simulations
	if len(ns) == 0 {
		return nil
	}

	if isCm {
		return k.createCm(ns, sid, guardianSpec)
	} else {
		return k.createCrd(ns, sid, guardianSpec)
	}
}

// setCm - Set a Guardian Config Map (Update if exists, create if not)
// In case the read ConfigMap is corrupted, try to update using a well structured one
// Using a client side Read then Write sequence.
// In rare cases, the CM may be updated after the read and before the write which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) setCm(ns string, sid string, guardianSpec *spec.GuardianSpec) error {
	var gBytes []byte
	var err error
	var cm *corev1.ConfigMap
	cmName := "guardian." + sid

	if cm, err = k.cmClient.CoreV1().ConfigMaps(ns).Get(context.TODO(), cmName, metav1.GetOptions{}); err != nil {
		// Failed to read configmap
		if !errors.IsNotFound(err) {
			return fmt.Errorf("set configmap %s: error reading guardian %w", cmName, err)
		}

		if err = k.createCm(ns, sid, guardianSpec); err != nil {
			return fmt.Errorf("set configmap %s: %w", cmName, err)
		}
		return nil
	}

	// ConfigMap exists - lets update it
	g := new(spec.GuardianSpec)

	gData, ok := cm.Data["Guardian"]
	if ok && len(gData) > 0 {
		// Unmarshal Guardian if you can
		if err = json.Unmarshal([]byte(gData), g); err != nil {
			// Guardian corrupted
			cm.Data = make(map[string]string, 1)
		}
	} else {
		// Guardian corrupted
		cm.Data = make(map[string]string, 1)
	}

	if guardianSpec != nil {
		if guardianSpec.Control != nil {
			g.Control = guardianSpec.Control
		}
		if guardianSpec.Configured != nil {
			g.Configured = guardianSpec.Configured
		}
		if guardianSpec.Learned != nil {
			g.Learned = guardianSpec.Learned
		}
	}

	if gBytes, err = json.Marshal(g); err != nil {
		return fmt.Errorf("set configmap %s: error marshaling data %w", cmName, err)
	}
	cm.Data["Guardian"] = string(gBytes)

	if _, err = k.cmClient.CoreV1().ConfigMaps(ns).Update(context.TODO(), cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("set configmap %s: error updating resource %w", cmName, err)
	}

	return nil
}

// Set a Guardian CRD (Update if exists, create if not)
// In case the read CRD is corrupted, try to update using a well structured one
// Using a client side Read then Write sequence.
// In rare cases, the CRD may be updated after the read and before the write which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose of guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) setCrd(ns string, sid string, guardianSpec *spec.GuardianSpec) error {
	var g *spec.Guardian
	var err error

	if g, err = k.crdClient.Guardians(ns).Get(context.TODO(), sid, metav1.GetOptions{}); err != nil {
		// Failed to read CRD
		if !errors.IsNotFound(err) {
			return fmt.Errorf("set crd ns %s sid %s: error reading guardian %w", ns, sid, err)
		}

		if err = k.createCrd(ns, sid, guardianSpec); err != nil {
			return fmt.Errorf("set crd ns %s sid %s: %w", ns, sid, err)
		}
		return nil
	}

	// CRD exists - lets update it
	g.Name = sid
	if g.Spec == nil {
		g.Spec = new(spec.GuardianSpec)
	}
	if guardianSpec != nil {
		if guardianSpec.Control != nil {
			g.Spec.Control = guardianSpec.Control
		}
		if guardianSpec.Configured != nil {
			g.Spec.Configured = guardianSpec.Configured
		}
		if guardianSpec.Learned != nil {
			g.Spec.Learned = guardianSpec.Learned
		}
	}

	if _, err = k.crdClient.Guardians(ns).Update(context.TODO(), g, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("set crd ns %s sid %s: updating resource %w", ns, sid, err)
	}

	return nil
}

// Set - Set a Guardian resource (Config Map or CRD)
// Use update if exists, create if not
// In case the resource read is corrupted, try to update using a well structured one
// Using a client side Read then Write sequence.
// In rare cases, the resource may be updated after the read and before the write which will
// result in failure to write the data. This may happen for example when a manual update
// is performed in parallel to an update from the guard-service.
// Lose of manual updates is reported to the user which will normally retry.
// Lose guard-service updates occurs periodically such that data is not lost
func (k *KubeMgr) Set(ns string, sid string, isCm bool, guardianSpec *spec.GuardianSpec) error {
	// Skip during simulations
	if len(ns) == 0 {
		return nil
	}

	if isCm {
		return k.setCm(ns, sid, guardianSpec)
	} else {
		return k.setCrd(ns, sid, guardianSpec)
	}
}

// GetGuardian - Returns a Guardian that was read from Crd or from ConfigMap or an auto-activated Guardian
// Never returns nil
// ns is the namespace being used
// sid is the service identifier being used
// cm if true a ConfigMap, otherwise a CRD
// autoActivate  - if true, when a default guardian is returned, set it to auto activate mod
func (k *KubeMgr) GetGuardian(ns string, sid string, cm bool, autoActivate bool) *spec.GuardianSpec {
	var g *spec.GuardianSpec
	var err error

	// Skip during simulations, or if illegal sid
	if len(ns) > 0 && !strings.EqualFold(sid, "ns-"+ns) {
		// legal sid
		if cm {
			g, err = k.readCm(ns, sid)
			if err != nil {
				// try the namespace default guardian
				g, _ = k.readCm(ns, "ns-"+ns)
				pi.Log.Debugf("Read Guardian from ConfigMap for ns %s, sid %s", ns, sid)
			}
		} else {
			g, err = k.readCrd(ns, sid)
			if err != nil {
				// try the namespace default crd
				g, _ = k.readCrd(ns, "ns-"+ns)
				pi.Log.Debugf("Read Guardian from CRD for ns %s, sid %s", ns, sid)
			}
		}
	}

	if g == nil {
		pi.Log.Debugf("Create default Guardian for ns %s, sid %s", ns, sid)

		// create a default guardian and return it
		g = new(spec.GuardianSpec)
		// a default guardianSpec has:
		//		Auto = false, Learn = false, Force = false, Alert = false, Block=false
		if autoActivate {
			g.SetToMaximalAutomation()
			// now guardianSpec has:
			//		Auto = true, Learn = true, Force = true, Alert = true, Block=false
		}
	}
	return g
}
