package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Auth struct {
	AccessKey     string `json:"access_key"`
	SecretKey     string `json:"secret_key"`
	ServerAddress string `json:"server_address"`
}

func NewAuth(accessKey, secretKey, serverAddress string) *Auth {
	return &Auth{
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		ServerAddress: serverAddress,
	}
}

func Upload_bind_reload(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	certStr, ok := cfg["cert"].(string)
	if !ok || certStr == "" {
		return nil, fmt.Errorf("cert is required and must be a string")
	}
	keyStr, ok := cfg["key"].(string)
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("key is required and must be a string")
	}
	accessKey, ok := cfg["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("access_key is required and must be a string")
	}
	secretKey, ok := cfg["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("secret_key is required and must be a string")
	}
	serverAddress, ok := cfg["server_address"].(string)
	if !ok || serverAddress == "" {
		return nil, fmt.Errorf("server_address is required and must be a string")
	}
	domains, ok := cfg["domain"].([]interface{})
	if !ok || len(domains) == 0 {
		return nil, fmt.Errorf("domain is required and must be a []interface{}")
	}
	domain := make([]string, len(domains))
	for i, v := range domains {
		if str, ok := v.(string); ok {
			domain[i] = str
		} else {
			// 如果断言失败，可以处理错误
			return nil, fmt.Errorf("element at index %d is not a string", i)
		}
	}
	sha256, err := GetSHA256(certStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHA256 of cert: %w", err)
	}
	note := fmt.Sprintf("allinssl-%s", sha256)

	a := NewAuth(accessKey, secretKey, serverAddress)
	// 检查证书是否已存在于服务器
	// 只根据证书名称检查是否存在，格式为 "allinssl-<sha256>"
	certServer, err := a.listCertFromCloud()
	if err != nil {
		return nil, fmt.Errorf("failed to list certs from Cloud: %w", err)
	}
	var certID float64
	for _, cert := range certServer {
		if cert["cert_name"] == note {
			certID, ok = cert["id"].(float64)
			if !ok {
				certID = 0
			}
		}
	}
	// 如果证书不存在，则上传证书
	if certID == 0 {
		certID, err = a.uploadCertToCloud(certStr, keyStr, note)
		if err != nil || certID == 0 {
			return nil, fmt.Errorf("failed to upload to Cloud: %w", err)
		}
	}
	bindRes, err := a.bindCertToCloud(certID, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to bind cert to Cloud: %w", err)
	}
	// 如果绑定失败，返回错误
	if bindRes {
		// 重载 Cloud
		err = a.reloadFromCloud()
		if err != nil {
			return nil, fmt.Errorf("failed to reload from Cloud: %w", err)
		}
	}
	return &Response{
		Status:  "success",
		Message: "Certificate uploaded and bound and rload successfully",
		Result:  map[string]interface{}{"message": "重载成功"},
	}, nil
}

func Upload_bind(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	certStr, ok := cfg["cert"].(string)
	if !ok || certStr == "" {
		return nil, fmt.Errorf("cert is required and must be a string")
	}
	keyStr, ok := cfg["key"].(string)
	if !ok || keyStr == "" {
		return nil, fmt.Errorf("key is required and must be a string")
	}
	accessKey, ok := cfg["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("access_key is required and must be a string")
	}
	secretKey, ok := cfg["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("secret_key is required and must be a string")
	}
	serverAddress, ok := cfg["server_address"].(string)
	if !ok || serverAddress == "" {
		return nil, fmt.Errorf("server_address is required and must be a string")
	}
	domains, ok := cfg["domain"].([]interface{})
	if !ok || len(domains) == 0 {
		return nil, fmt.Errorf("domain is required and must be a []interface{}")
	}
	domain := make([]string, len(domains))
	for i, v := range domains {
		if str, ok := v.(string); ok {
			domain[i] = str
		} else {
			// 如果断言失败，可以处理错误
			return nil, fmt.Errorf("element at index %d is not a string", i)
		}
	}
	sha256, err := GetSHA256(certStr)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHA256 of cert: %w", err)
	}
	note := fmt.Sprintf("allinssl-%s", sha256)

	a := NewAuth(accessKey, secretKey, serverAddress)
	// 检查证书是否已存在于服务器
	// 只根据证书名称检查是否存在，格式为 "allinssl-<sha256>"
	certServer, err := a.listCertFromCloud()
	if err != nil {
		return nil, fmt.Errorf("failed to list certs from Cloud: %w", err)
	}
	var certID float64
	for _, cert := range certServer {
		if cert["cert_name"] == note {
			certID, ok = cert["id"].(float64)
			if !ok {
				certID = 0
			}
		}
	}
	// 如果证书不存在，则上传证书
	if certID == 0 {
		certID, err = a.uploadCertToCloud(certStr, keyStr, note)
		if err != nil || certID == 0 {
			return nil, fmt.Errorf("failed to upload to Cloud: %w", err)
		}
	}
	_, err = a.bindCertToCloud(certID, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to bind cert to Cloud: %w", err)
	}
	return &Response{
		Status:  "success",
		Message: "Certificate uploaded and bound successfully",
		Result:  map[string]interface{}{"message": "绑定成功"},
	}, nil
}

func Reload(cfg map[string]any) (*Response, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	accessKey, ok := cfg["access_key"].(string)
	if !ok || accessKey == "" {
		return nil, fmt.Errorf("access_key is required and must be a string")
	}
	secretKey, ok := cfg["secret_key"].(string)
	if !ok || secretKey == "" {
		return nil, fmt.Errorf("secret_key is required and must be a string")
	}
	serverAddress, ok := cfg["server_address"].(string)
	if !ok || serverAddress == "" {
		return nil, fmt.Errorf("server_address is required and must be a string")
	}

	a := NewAuth(accessKey, secretKey, serverAddress)
	// 重载 Cloud
	err := a.reloadFromCloud()
	if err != nil {
		return nil, fmt.Errorf("failed to reload from Cloud: %w", err)
	}

	return &Response{
		Status:  "success",
		Message: "Certificate reload successfully",
		Result: map[string]interface{}{
			"message": "重载成功",
		},
	}, nil
}

func (a Auth) uploadCertToCloud(cert, key, note string) (float64, error) {
	params := map[string]any{
		"cert":      cert,
		"key":       key,
		"cert_name": note,
	}

	res, err := a.CloudAPI("/cert/upload", params, true)
	if err != nil {
		return 0, fmt.Errorf("failed to call Cloud API: %w", err)
	}
	code, ok := res["code"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid response format: code not found")
	}
	if code != 200 {
		return 0, fmt.Errorf("cloud API error: %s", res["msg"])
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return 0, fmt.Errorf("invalid response format: data not found")
	}
	certID, ok := data["id"].(float64)
	if !ok {
		return 0, fmt.Errorf("invalid response format: id not found")
	}
	return certID, nil
}

func (a Auth) bindCertToCloud(certID float64, domain []string) (bool, error) {
	params := map[string]interface{}{
		"id":     certID,
		"domain": domain,
	}
	res, err := a.CloudAPI("/cert/bind", params, true)
	if err != nil {
		return false, fmt.Errorf("failed to call Cloud API: %w", err)
	}
	code, ok := res["code"].(float64)
	if !ok {
		return false, fmt.Errorf("invalid response format: code not found")
	}
	if code != 200 {
		return false, fmt.Errorf("cloud API error: %s", res["msg"])
	}
	data, ok := res["data"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid response format: data not found")
	}
	return data, nil

}

func (a Auth) listCertFromCloud() ([]map[string]any, error) {
	res, err := a.CloudAPI("/cert/certlist", map[string]interface{}{}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to call Cloud API: %w", err)
	}
	code, ok := res["code"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid response format: code not found")
	}
	if code != 200 {
		return nil, fmt.Errorf("cloud API error: %s", res["msg"])
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid response format: data not found")
	}
	certList, ok := data["certs"].([]any)
	if !ok {
		return nil, fmt.Errorf("invalid response format: certs not found")
	}
	certs := make([]map[string]any, 0, len(certList))
	for _, cert := range certList {
		certMap, ok := cert.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid response format: cert item is not a map")
		}
		certs = append(certs, certMap)
	}
	return certs, nil
}

func (a Auth) reloadFromCloud() error {
	res, err := a.CloudAPI("/reload", map[string]interface{}{}, true)
	if err != nil {
		return fmt.Errorf("failed to call Cloud API: %w", err)
	}
	code, ok := res["code"].(float64)
	if !ok {
		return fmt.Errorf("invalid response format: code not found")
	}
	if code != 200 {
		return fmt.Errorf("cloud API error: %s", res["msg"])
	}
	return nil
}

func hmacSHA256(key, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// CloudAPI
func (a Auth) CloudAPI(apiPath string, data map[string]interface{}, jsonMode bool) (map[string]interface{}, error) {
	AccessKey := a.AccessKey
	SecretKey := a.SecretKey

	body := ""
	mime := ""
	if jsonMode {
		_body, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		body = string(_body)
		mime = "application/json"
	} else {
		values := url.Values{}
		for k, v := range data {
			values.Set(k, v.(string))
		}
		body = values.Encode()
		mime = "application/x-www-form-urlencoded"
	}
	values := url.Values{}
	for k, v := range data {
		values.Add(k, fmt.Sprintf("%v", v))
	}
	now := time.Now()
	timestamp := fmt.Sprintf("%d", now.Unix())
	values.Add("x-timestamp", timestamp)
	values.Add("x-app", "allinssl")
	values.Add("x-accesskey", AccessKey)
	values.Add("x-path", apiPath)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	signStr := ""
	for _, k := range keys {
		signStr += fmt.Sprintf("%s=%s&", k, values.Get(k))
	}
	signStr = signStr[:len(signStr)-1]
	// 计算签名
	// 使用 HMAC-SHA256 签名算法
	Authorization := hmacSHA256(SecretKey, signStr)
	req, err := http.NewRequest("POST", a.ServerAddress+apiPath, strings.NewReader(body))
	if err != nil {
		return nil, err // 创建请求错误
	}
	req.Header.Add("Content-Type", mime)
	req.Header.Add("Authorization", Authorization)
	req.Header.Add("x-timestamp", timestamp)
	req.Header.Add("x-app", "allinssl")
	req.Header.Add("x-accesskey", AccessKey)
	req.Header.Add("x-path", apiPath)
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	} // 网络错误
	defer resp.Body.Close()
	r, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err // 读取响应错误
	}
	var result map[string]interface{}

	err = json.Unmarshal(r, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
