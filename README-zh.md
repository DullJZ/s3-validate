# s3-validate

中文 | [English](README.md)

`s3-validate` 是一个轻量级的 Golang 包，用于在服务端校验使用 AWS Signature Version 4 签名的 S3 请求。它同时支持基于请求头的签名与预签名 URL，适合需要验证客户端发起上传或下载请求的后端服务。

## 功能特性

- ✅ 校验 S3 REST 请求的 AWS Signature V4 签名
- ✅ 同时支持 `Authorization` 头与预签名查询参数两种签名方式
- ✅ 支持自定义凭证提供者，可接入数据库或密钥管理系统
- ✅ 可配置的时间偏移容差与预签名 URL 过期时间控制

## 安装

```bash
go get github.com/DullJZ/s3-validate
```

## 快速上手

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/DullJZ/s3-validate"
)

type memoryProvider map[string]string

func (m memoryProvider) SecretKey(ctx context.Context, accessKey string) (string, error) {
    key, ok := m[accessKey]
    if !ok {
        return "", fmt.Errorf("未知的访问密钥 %s", accessKey)
    }
    return key, nil
}

func main() {
    verifier := &s3validate.Verifier{
        Credentials: memoryProvider{
            "AKIDEXAMPLE": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        },
    }

    http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
        if _, err := verifier.Verify(r.Context(), r); err != nil {
            http.Error(w, err.Error(), http.StatusUnauthorized)
            return
        }
        w.WriteHeader(http.StatusOK)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### 自定义行为

- **AllowedClockSkew** —— 设置 `Verifier.AllowedClockSkew`，自定义允许的时间偏移（默认为 5 分钟）。
- **Now** —— 设置 `Verifier.Now` 提供自定义时间源，便于进行可重复的单元测试。

## 测试

项目内置了来自 AWS 官方文档的示例用例，用于确保校验逻辑与 SigV4 标准保持一致：

```bash
go test ./...
```

## 许可证

MIT
