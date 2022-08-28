package server

import (
	"fmt"
	"go.uber.org/zap"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func WatchSecret(client kubernetes.Interface, namespace, labelSelector string, stop <-chan struct{}, p *AuthProcessor) error {
	selector, err := labels.Parse(labelSelector)
	if err != nil {
		return err
	}

	factory := informers.NewSharedInformerFactoryWithOptions(client, time.Hour, informers.WithNamespace(namespace))
	factory.Core().V1().Secrets().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}

			if selector.Matches(labels.Set(secret.Labels)) {
				if err := p.LoadFromSecret(nil, secret.Data); err != nil {
					logger.Error(fmt.Sprintf(`load config from secret "%s/%s" error`, secret.Namespace, secret.Name), zap.String("func", "WatchSecret"))
				}
			}
		},
		UpdateFunc: func(old, new interface{}) {
			secretOld, okOld := old.(*corev1.Secret)
			secretNew, okNew := new.(*corev1.Secret)
			if !okOld || !okNew {
				return
			}
			matchOld := selector.Matches(labels.Set(secretOld.Labels))
			matchNew := selector.Matches(labels.Set(secretNew.Labels))

			var err error
			if matchOld && matchNew {
				err = p.LoadFromSecret(secretOld.Data, secretNew.Data)
			} else if matchOld {
				err = p.LoadFromSecret(secretOld.Data, nil)
			} else if matchNew {
				err = p.LoadFromSecret(nil, secretNew.Data)
			}
			if err != nil {
				logger.Error(fmt.Sprintf(`update config from secret "%s/%s" error`, secretNew.Namespace, secretNew.Name), zap.String("func", "WatchSecret"))
			}
		},
		DeleteFunc: func(obj interface{}) {
			secret, ok := obj.(*corev1.Secret)
			if !ok {
				return
			}
			if selector.Matches(labels.Set(secret.Labels)) {
				if err := p.LoadFromSecret(secret.Data, nil); err != nil {
					logger.Error(fmt.Sprintf(`remove config from secret "%s/%s" error`, secret.Namespace, secret.Name), zap.String("func", "WatchSecret"))
				}
			}
		},
	})
	factory.Start(stop)
	for _, r := range factory.WaitForCacheSync(stop) {
		if !r {
			return fmt.Errorf("informer failed to WaitForCacheSync")
		}
	}
	return nil
}
