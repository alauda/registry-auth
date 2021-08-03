library "alauda-cicd"
def language = "golang"
AlaudaPipeline{
  config = [
    agent: 'golang-1.15',
    folder: '.',
    chart: [],
    scm: [
      credentials: 'alaudabot'
    ],
    docker: [
      repository: "ait/registry-auth",
      context: ".",
      dockerfile: "build/docker/registry-auth.Dockerfile",
    ],
    sonar: [
      binding: "sonarqube"
    ],
  ]
  env = [
    GO111MODULE: "on",
    GONOSUMDB: "bitbucket.org/mathildetech/*,gomod.alauda.cn/*,gitlab-ce.alauda.cn/*",
    GOPROXY: "https://athens.alauda.cn,direct",
  ]
  steps = [
    [
      name: "Build",
      container: language,
      commands: [
        "make",
        "sed -i 's|build-harbor|harbor-b|g' build/docker/registry-auth.Dockerfile"
      ]
    ]
  ]
}

