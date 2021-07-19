# Registry-Auth

1. 参数说明

    |          命令行参数       |            默认值          |                     说明
    |            ---          |             ---           |                     ---
    | --server-bind-address   |                           | Sever监听的IP，默认监听所有
    | --server-port           | 8080                      | Sever监听的端口
    | --server-tls-cert-file  |                           | Sever的证书路径，可选，不选则以HTTP方式工作
    | --server-tls-key-file   |                           | Sever的证书路径，可选
    | --auth-public-cert-file |                           | 签发JWT使用的证书路径，必填
    | --auth-private-key-file |                           | 签发JWT使用的Key路径，必填
    | --auth-config-file      |                           | 认证配置文件路径，可选
    | --auth-config-namespace |                           | 认证配置所在命名空间，可选
    | --auth-config-selector  | registry-auth-config=true | 认证配置所在保密字典的选择器，可选
    | --auth-token-duration   | 600                       | JWT的有效时长，单位：秒
    | --auth-issuer           | registry-token-issuer     | JWT的签发者名称
    | --registry-backend      | 127.0.0.1:5000            | 代理后端registry的地址，可选
    | --kubeconfig            |                           | 访问k8s的配置文件路径，可选，认证配置命名空间非空时必填
    | --log-level             | info                      | 日志级别

2. 权限配置文件格式

    ``` yaml
    users:
      user1: password1           # 使用明文密码
      user2: $2y$05$o.txf8NBl17CimmIKybYYe9SmIcAzctQ84.UbFCObPFxt78W1DEJW # 使用bcrypt加密后的密码，可用命令：`htpasswd -nbB user2 password2` 生成加密后的密码
    auths:
      user1:                     # user1的权限配置
      - target: usersrepo/test1  # repoistory名称
        actions:                 # 允许的操作
        - pull
        - push
      - target: team1repo/.*     # 使用正则表达式表示匹配的repoistory名称
        useRegexp: true          # 表示target是使用了正则表达式
        actions:
        - pull
      _anonymous:                # 配置匿名用户的权限，匿名用户登录时不需要提供用户名密码
      - target: tkestack/.* 
        useRegexp: true 
        actions:
        - pull
    ```

    在保密字典中存放的认真配置文件与上述结构相同，在保密字典中使用的key是config。

    保密字典中配置的优先级高于文件中的配置。

3. Docker Registry配置说明

    在 /etc/docker/registry/config.yml中配置如下字段：

    ``` yaml
    auth:                                                  
      token:                                               
        autoredirect: false                                # 关闭自动重定向
        realm: https://192.168.254.1:18080/auth/token      # realm将返回给docker客户端，需要填写docker可访问到的registry-auth的url
        service: token-service                             # 用于认证方区分不同的registry实例，目前没使用此特性, 固定为token-service即可
        issuer: registry-token-issuer                      # 与--auth-issuer保持一致
        rootcertbundle: /tmp/tls.crt                       # 与--auth-public-cert-file保持一致
    ```

    等价的ENV配置为

    ``` yaml
    env:
    - name: REGISTRY_TOKEN_AUTOREDIRECT
      value: "false"
    - name: REGISTRY_TOKEN_REALM
      value: https://192.168.254.1:18080/auth/token
    - name: REGISTRY_TOKEN_SERVICE
      value: token-service
    - name: REGISTRY_TOKEN_ISSER
      value: registry-token-issuer
    - name: REGISTRY_TOKEN_ROOTCERTBUNDLE
      value: /tmp/tls.crt
    ```
