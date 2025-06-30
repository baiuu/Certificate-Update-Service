package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type ActionInfo struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Params      map[string]any `json:"params,omitempty"`
}

type Request struct {
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params"`
}

type Response struct {
	Status  string                 `json:"status"`
	Message string                 `json:"message"`
	Result  map[string]interface{} `json:"result"`
}

var pluginMeta = map[string]interface{}{
	"name":        "server_cloud_api",
	"description": "本地服务器云 API 插件",
	"version":     "1.0.0",
	"author":      "baiuu",
	"config": map[string]interface{}{
		"access_key":     "AccessKey",
		"secret_key":     "SecretKey",
		"server_address": "服务地址",
	},
	"actions": []ActionInfo{
		{
			Name:        "upload_bind_reload",
			Description: "上传绑定并重载",
			Params: map[string]interface{}{
				"domain": []string{"域名1", "域名2"},
			},
		},
		{
			Name:        "upload_bind",
			Description: "上传绑定",
			Params: map[string]interface{}{
				"domain": []string{"域名1", "域名2"},
			},
		},
		{
			Name:        "reload",
			Description: "重载",
		},
	},
}

func GetSHA256(certStr string) (string, error) {
	certPEM := []byte(certStr)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("无法解析证书 PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("解析证书失败: %v", err)
	}

	sha256Hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sha256Hash[:]), nil
}

func outputJSON(resp *Response) {
	_ = json.NewEncoder(os.Stdout).Encode(resp)
}

func outputError(msg string, err error) {
	outputJSON(&Response{
		Status:  "error",
		Message: fmt.Sprintf("%s: %v", msg, err),
	})
}

func main() {
	var req Request
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		outputError("读取输入失败", err)
		return
	}

	if err := json.Unmarshal(input, &req); err != nil {
		outputError("解析请求失败", err)
		return
	}

	switch req.Action {
	case "get_metadata":
		outputJSON(&Response{
			Status:  "success",
			Message: "插件信息",
			Result:  pluginMeta,
		})
	case "list_actions":
		outputJSON(&Response{
			Status:  "success",
			Message: "支持的动作",
			Result:  map[string]interface{}{"actions": pluginMeta["actions"]},
		})
	case "upload_bind_reload":
		rep, err := Upload_bind_reload(req.Params)
		if err != nil {
			outputError("本地云主机部署失败：", err)
			return
		}
		outputJSON(rep)
	case "upload_bind":
		rep, err := Upload_bind(req.Params)
		if err != nil {
			outputError("本地云主机部署失败：", err)
			return
		}
		outputJSON(rep)
	case "reload":
		rep, err := Reload(req.Params)
		if err != nil {
			outputError("重载失败", err)
			return
		}
		outputJSON(rep)
	default:
		outputJSON(&Response{
			Status:  "error",
			Message: "未知 action: " + req.Action,
		})
	}
}
