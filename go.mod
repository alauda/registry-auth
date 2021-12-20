module gomod.alauda.cn/registry-auth

go 1.15

replace (
	github.com/chartmuseum/storage => github.com/choujimmy/storage v0.0.0-20200507092433-6aea2df34764
	k8s.io/client-go => k8s.io/client-go v0.20.6
	tkestack.io/tke => gomod.alauda.cn/tke v0.0.0-20210408015336-086f29649704
)

require (
	github.com/cssivision/reverseproxy v0.0.1
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7
	github.com/emicklei/go-restful v2.15.0+incompatible
	github.com/go-openapi/spec v0.19.4 // indirect
	github.com/google/uuid v1.1.2
	github.com/gopherjs/gopherjs v0.0.0-20191106031601-ce3c9ade29de // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/juju/testing v0.0.0-20200608005635-e4eedbc6f7aa // indirect
	github.com/onsi/gomega v1.7.1 // indirect
	github.com/pkg/errors v0.9.1
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.6.2
	github.com/thoas/go-funk v0.9.1 // indirect
	go.uber.org/atomic v1.5.0 // indirect
	go.uber.org/zap v1.10.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	gomod.alauda.cn/alauda-backend v0.2.13
	gomod.alauda.cn/app v1.0.3
	gomod.alauda.cn/log v1.0.6
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/square/go-jose.v2 v2.2.2
	k8s.io/api v0.20.6
	k8s.io/apimachinery v0.20.6
	k8s.io/apiserver v0.18.2 // indirect
	k8s.io/client-go v12.0.0+incompatible
)
