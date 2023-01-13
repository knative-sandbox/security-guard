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
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	spec "knative.dev/security-guard/pkg/apis/guard/v1alpha1"
	guardfake "knative.dev/security-guard/pkg/client/clientset/versioned/fake"
	guardv1alpha1 "knative.dev/security-guard/pkg/client/clientset/versioned/typed/guard/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func fakeGetInclusterConfig() (*rest.Config, error) {
	return nil, nil
}

func TestKubeMgr_ReadCm(t *testing.T) {
	type fields struct {
		kclientset *k8sfake.Clientset
	}
	tests := []struct {
		name    string
		fields  fields
		want    *spec.GuardianSpec
		wantErr bool
	}{
		{
			name: "missing",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "xx_guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					}})},
			want:    nil,
			wantErr: true,
		},
		{
			name: "malformed",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					}})},
			want:    nil,
			wantErr: true,
		},
		{
			name: "empty guardian",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": ""},
				})},
			want:    nil,
			wantErr: true,
		},
		{
			name: "cant marshal",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": "abc"},
				})},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ok",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": "{\"control\": {}}"},
				})},
			want:    &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(KubeMgr)
			k.getConfigFunc = fakeGetInclusterConfig
			k.cmClient = tt.fields.kclientset
			k.crdClient = guardfake.NewSimpleClientset().GuardV1alpha1()
			k.getConfigs()
			got, err := k.Read("ns", "sid", true)
			if (err != nil) != tt.wantErr {
				t.Errorf("KubeMgr.ReadCm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubeMgr.ReadCm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubeMgr_ReadCrd(t *testing.T) {
	type fields struct {
		gclientset guardv1alpha1.GuardV1alpha1Interface
	}
	tests := []struct {
		name    string
		fields  fields
		want    *spec.GuardianSpec
		wantErr bool
	}{
		{
			name: "missing",
			fields: fields{
				gclientset: guardfake.NewSimpleClientset().GuardV1alpha1(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "ok",
			fields: fields{
				gclientset: guardfake.NewSimpleClientset(&spec.Guardian{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Spec: &spec.GuardianSpec{
						Control: &spec.Ctrl{},
					},
				}).GuardV1alpha1(),
			},
			want:    &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(KubeMgr)
			k.getConfigFunc = fakeGetInclusterConfig
			k.cmClient = k8sfake.NewSimpleClientset()
			k.crdClient = tt.fields.gclientset
			k.getConfigs()
			got, err := k.Read("ns", "sid", false)
			if (err != nil) != tt.wantErr {
				t.Errorf("KubeMgr.ReadCrd() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KubeMgr.ReadCrd() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKubeMgr_CreateCm(t *testing.T) {

	t.Run("create", func(t *testing.T) {
		k := new(KubeMgr)
		k.getConfigFunc = fakeGetInclusterConfig
		k.cmClient = k8sfake.NewSimpleClientset()
		k.crdClient = guardfake.NewSimpleClientset().GuardV1alpha1()
		k.getConfigs()

		g := &spec.GuardianSpec{
			Control: &spec.Ctrl{},
		}
		if err := k.Create("myns", "mysid", true, g); err != nil {
			t.Errorf("KubeMgr.CreateCm() error = %v", err)
		}

		_, err := k.Read("ns", "sid", true)
		if err == nil {
			t.Errorf("KubeMgr.ReadCm() Expected an error!")
			return
		}

		got, err := k.Read("myns", "mysid", true)
		if err != nil {
			t.Errorf("KubeMgr.ReadCm() unexpected error = %v", err)
			return
		}
		if !reflect.DeepEqual(got, g) {
			t.Errorf("KubeMgr.ReadCm() = %v, want %v", got, g)
		}
	})
}

func TestKubeMgr_CreateCrd(t *testing.T) {
	t.Run("create", func(t *testing.T) {

		k := new(KubeMgr)
		k.getConfigFunc = fakeGetInclusterConfig
		k.cmClient = k8sfake.NewSimpleClientset()
		k.crdClient = guardfake.NewSimpleClientset().GuardV1alpha1()
		k.getConfigs()

		g := &spec.GuardianSpec{
			Control: &spec.Ctrl{},
		}
		if err := k.Create("myns", "mysid", false, g); err != nil {
			t.Errorf("KubeMgr.CreateCrd() error = %v", err)
		}

		_, err := k.Read("ns", "sid", false)
		if err == nil {
			t.Errorf("KubeMgr.ReadCrd() Expected an error!")
			return
		}

		got, err := k.Read("myns", "mysid", false)
		if err != nil {
			t.Errorf("KubeMgr.ReadCrd() unexpected error = %v", err)
			return
		}
		if !reflect.DeepEqual(got, g) {
			t.Errorf("KubeMgr.ReadCrd() = %v, want %v", got, g)
		}
	})
}

func TestKubeMgr_SetCm(t *testing.T) {
	type fields struct {
		kclientset *k8sfake.Clientset
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "missing",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "xx_guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					}})},
		},
		{
			name: "malformed",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					}})},
		},
		{
			name: "empty guardian",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": ""},
				})},
		},
		{
			name: "cant marshal",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": "abc"},
				})},
		},
		{
			name: "ok",
			fields: fields{
				kclientset: k8sfake.NewSimpleClientset(&v1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "guardian.sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Data: map[string]string{"Guardian": "{\"control\": {}}"},
				})},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			var got *spec.GuardianSpec
			k := new(KubeMgr)
			k.getConfigFunc = fakeGetInclusterConfig
			k.cmClient = tt.fields.kclientset
			k.crdClient = guardfake.NewSimpleClientset().GuardV1alpha1()
			k.getConfigs()

			g := &spec.GuardianSpec{
				Control: &spec.Ctrl{},
			}

			if err := k.Set("ns", "sid", true, g); err != nil {
				t.Errorf("KubeMgr.SetCm() error = %v", err)
			}

			_, err = k.Read("xxns", "xxsid", true)
			if err == nil {
				t.Errorf("KubeMgr.ReadCm() Expected an error!")
				return
			}

			got, err = k.Read("ns", "sid", true)
			if err != nil {
				t.Errorf("KubeMgr.ReadCm() unexpected error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, g) {
				t.Errorf("KubeMgr.ReadCm() = %v, want %v", got, g)
			}
		})
	}
}

func TestKubeMgr_SetCrd(t *testing.T) {
	type fields struct {
		gclientset guardv1alpha1.GuardV1alpha1Interface
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "missing",
			fields: fields{
				gclientset: guardfake.NewSimpleClientset().GuardV1alpha1(),
			},
		},
		{
			name: "ok",
			fields: fields{
				gclientset: guardfake.NewSimpleClientset(&spec.Guardian{
					ObjectMeta: metav1.ObjectMeta{
						Name:        "sid",
						Namespace:   "ns",
						Annotations: map[string]string{},
					},
					Spec: &spec.GuardianSpec{
						Control: &spec.Ctrl{},
					},
				}).GuardV1alpha1(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(KubeMgr)
			k.getConfigFunc = fakeGetInclusterConfig
			k.cmClient = k8sfake.NewSimpleClientset()
			k.crdClient = tt.fields.gclientset
			k.getConfigs()

			g := &spec.GuardianSpec{
				Control: &spec.Ctrl{},
			}
			if err := k.Set("ns", "sid", false, g); err != nil {
				t.Errorf("KubeMgr.SetCrd() error = %v", err)
			}

			_, err := k.Read("xxns", "xxsid", false)
			if err == nil {
				t.Errorf("KubeMgr.ReadCrd() Expected an error!")
				return
			}

			got, err := k.Read("ns", "sid", false)
			if err != nil {
				t.Errorf("KubeMgr.ReadCrd() unexpected error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, g) {
				t.Errorf("KubeMgr.ReadCrd() = %v, want %v", got, g)
			}
		})
	}
}

func TestKubeMgr_ReadGuardian(t *testing.T) {
	type args struct {
		ns           string
		sid          string
		cm           bool
		autoActivate bool
	}
	tests := []struct {
		name string
		args args
		want *spec.GuardianSpec
	}{
		{
			name: "cm",
			args: args{
				ns:           "ns",
				sid:          "sid",
				cm:           true,
				autoActivate: false,
			},
			want: &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
		},
		{
			name: "crd",
			args: args{
				ns:           "ns",
				sid:          "sid",
				cm:           false,
				autoActivate: false,
			},
			want: &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
		},
		{
			name: "cm auto",
			args: args{
				ns:           "ns",
				sid:          "sid",
				cm:           true,
				autoActivate: true,
			},
			want: &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
		},
		{
			name: "crd auto",
			args: args{
				ns:           "ns",
				sid:          "sid",
				cm:           false,
				autoActivate: true,
			},
			want: &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := new(KubeMgr)
			k.getConfigFunc = fakeGetInclusterConfig

			// Use ns.sid
			want := &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil}
			k.cmClient = k8sfake.NewSimpleClientset(&v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "guardian.sid",
					Namespace:   "ns",
					Annotations: map[string]string{},
				},
				Data: map[string]string{"Guardian": "{\"control\": {}}"},
			})
			k.crdClient = guardfake.NewSimpleClientset(&spec.Guardian{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "sid",
					Namespace:   "ns",
					Annotations: map[string]string{},
				},
				Spec: &spec.GuardianSpec{
					Control: &spec.Ctrl{},
				},
			}).GuardV1alpha1()
			if got := k.GetGuardian(tt.args.ns, tt.args.sid, tt.args.cm, tt.args.autoActivate); !reflect.DeepEqual(got, want) {
				t.Errorf("KubeMgr.ReadGuardian() = %v, want %v", got, want)
			}

			// Use namespace defaults
			want = &spec.GuardianSpec{Control: &spec.Ctrl{}, Learned: nil, Configured: nil}
			k.cmClient = k8sfake.NewSimpleClientset(&v1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "guardian.ns-ns",
					Namespace:   "ns",
					Annotations: map[string]string{},
				},
				Data: map[string]string{"Guardian": "{\"control\": {}}"},
			})
			k.crdClient = guardfake.NewSimpleClientset(&spec.Guardian{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "ns-ns",
					Namespace:   "ns",
					Annotations: map[string]string{},
				},
				Spec: &spec.GuardianSpec{
					Control: &spec.Ctrl{},
				},
			}).GuardV1alpha1()
			if got := k.GetGuardian(tt.args.ns, tt.args.sid, tt.args.cm, tt.args.autoActivate); !reflect.DeepEqual(got, want) {
				t.Errorf("KubeMgr.ReadGuardian() = %v, want %v", got, want)
			}

			// Use guardian defaults
			if tt.args.autoActivate {
				want = &spec.GuardianSpec{Control: &spec.Ctrl{Auto: true, Learn: true, Force: true, Alert: true}, Learned: nil, Configured: nil}
			} else {
				want = &spec.GuardianSpec{Control: nil, Learned: nil, Configured: nil}
			}
			k.cmClient = k8sfake.NewSimpleClientset()
			k.crdClient = guardfake.NewSimpleClientset().GuardV1alpha1()
			if got := k.GetGuardian(tt.args.ns, tt.args.sid, tt.args.cm, tt.args.autoActivate); !reflect.DeepEqual(got, want) {
				t.Errorf("KubeMgr.ReadGuardian() = %v, want %v", got, want)
			}
		})
	}
}
func TestKubeMgr_Simulation(t *testing.T) {
	k := new(KubeMgr)
	k.getConfigFunc = fakeGetInclusterConfig
	t.Run("create", func(t *testing.T) {
		if got := k.GetGuardian("", "x", false, false); got == nil {
			t.Errorf("KubeMgr.GetGuardian() = should return default criteria during simulation")
		}
		if got, got2 := k.Read("", "x", false); got != nil || got2 != nil {
			t.Errorf("KubeMgr.Read() = %v, %v during simulation", got, got2)
		}
		if got := k.Set("", "x", false, nil); got != nil {
			t.Errorf("KubeMgr.Set() = %v during simulation", got)
		}
		if got := k.Create("", "x", false, nil); got != nil {
			t.Errorf("KubeMgr.Create() = %v during simulation", got)
		}

	})
}
