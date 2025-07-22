package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// 证书信息结构体
type Certificate struct {
	ID       int    `json:"id"`
	CertName string `json:"cert_name"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
}

// 绑定信息结构体
// 用于存储证书和域名的绑定关系
type Bind struct {
	CertID float64       `json:"id"`
	Domain []interface{} `json:"domain"`
}

// 配置信息结构体
type Config struct {
	Port    int  `json:"port"`
	IFiis   bool `json:"if_iis"` // 是否为 IIS 服务器
	Domains map[string]struct {
		CertAddress string `json:"cert"`
		KeyAddress  string `json:"key"`
		PfxAddress  string `json:"pfx"` // PFX 文件地址
	} `json:"domains"`
	BeforeExec string `json:"beforeexec"`
	AfterExec  string `json:"afterexec"`
	AccessKey  string `json:"accesskey"`
	SecretKey  string `json:"secretkey"`
}

var db *sql.DB
var config Config
var needreload bool

func main() {
	var err error
	// 打开数据库
	//cgoEnabled := os.Getenv("CGO_ENABLED")
	needreload = false
	//if cgoEnabled != "1" {
	//	log.Fatalf("CGO_ENABLED is not set to 1. Current value: %s", cgoEnabled)
	//}
	db, err = sql.Open("sqlite", "./certs.db")
	if err != nil {
		log.Fatalf("Unable to open database: %v", err)
	}
	defer db.Close()

	// 创建表
	createTable()
	// 加载配置文件
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	go func() {
		// 计算首次清理任务的执行时间
		nextCleanupTime := getNextCleanupTime()
		log.Printf("Next cleanup will run at: %v\n", nextCleanupTime)
		// 等待到下一次清理时间
		duration := time.Until(nextCleanupTime)
		log.Printf("Waiting for %v until next cleanup...\n", duration)
		for {
			time.Sleep(duration)

			// 执行清理任务
			if err := cleanUpUnboundCertificates(db); err != nil {
				log.Printf("Error cleaning up unbound certificates: %v", err)
			} else {
				log.Println("Cleanup task completed successfully")
			}

			// 计算下一次清理任务的执行时间
			nextCleanupTime = getNextCleanupTime()
			log.Printf("Next cleanup will run at: %v\n", nextCleanupTime)
			// 等待到下一次清理时间
			duration := time.Until(nextCleanupTime)
			log.Printf("Waiting for %v until next cleanup...\n", duration)
		}
	}()
	// 监听配置文件变化
	go watchConfigFile()

	// 初始化Gin
	gin.SetMode(gin.ReleaseMode)
        r := gin.New()

	// 注册POST接口
	r.POST("/cert/certlist", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 9200, "msg": err.Error()})
			return
		}
		headers := c.Request.Header
		if err := check_authorization(data, headers, "/cert/certlist"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 9201, "msg": "Unauthorized", "details": err.Error()})
			return
		}
		// 查询数据库获取证书列表
		rows, err := db.Query("SELECT id, cert_name, cert, key FROM certificates")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 9202, "msg": "Database query error", "details": err.Error()})
			return
		}
		defer rows.Close()
		var certs []Certificate
		for rows.Next() {
			var cert Certificate
			if err := rows.Scan(&cert.ID, &cert.CertName, &cert.Cert, &cert.Key); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 9203, "msg": "Database scan error", "details": err.Error()})
				return
			}
			certs = append(certs, cert)
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 9204, "msg": "Database rows error", "details": err.Error()})
			return
		}
		// 返回证书列表
		if len(certs) == 0 {
			certs = []Certificate{}
		}
		c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "data": gin.H{"certs": certs}})
	})

	r.POST("/cert/upload", func(c *gin.Context) {
		var cert Certificate
		if err := c.ShouldBindJSON(&cert); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 9200, "msg": err.Error()})
			return
		}
		headers := c.Request.Header
		// Convert cert struct to map[string]interface{}
		certMap := map[string]interface{}{
			"cert_name": cert.CertName,
			"cert":      cert.Cert,
			"key":       cert.Key,
		}
		if err := check_authorization(certMap, headers, "/cert/upload"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 9201, "msg": "Unauthorized", "details": err.Error()})
			return
		}
		// 插入证书到数据库
		cert.ID = insertCert(cert)
		c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "data": gin.H{"id": cert.ID}})
	})

	r.POST("/cert/bind", func(c *gin.Context) {
		var bind Bind
		if err := c.ShouldBindJSON(&bind); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 9200, "msg": err.Error()})
			return
		}
		headers := c.Request.Header
		// Convert cert struct to map[string]interface{}
		certMap := map[string]interface{}{
			"id":     bind.CertID,
			"domain": bind.Domain,
		}
		if err := check_authorization(certMap, headers, "/cert/bind"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 9201, "msg": "Unauthorized", "details": err.Error()})
			return
		}
		overlap := getOverlap(bind.Domain, config.Domains)
		if len(overlap) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"code": 9205, "msg": "No overlap with configured domains"})
			return
		}
		// 查询数据库，检查是否存在相同的 id 和 domain
		existingBind := validateDomain(bind.CertID, overlap)
		if existingBind {
			c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "data": false})
			return
		}
		// 如果没有错误，继续处理
		rows, err := db.Query("SELECT id, cert_name, cert, key FROM certificates WHERE id = ?", bind.CertID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 9202, "msg": "Database query error", "details": err.Error()})
			return
		}
		var cert Certificate
		if rows.Next() {
			if err := rows.Scan(&cert.ID, &cert.CertName, &cert.Cert, &cert.Key); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 9203, "msg": "Database scan error", "details": err.Error()})
				return
			}
		} else {
			c.JSON(http.StatusNotFound, gin.H{"code": 9206, "msg": "Certificate not found"})
			return
		}
		if err := rows.Err(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"code": 9204, "msg": "Database rows error", "details": err.Error()})
			return
		}
		rows.Close()
		if config.IFiis {
			for _, domain := range overlap {
				block, _ := pem.Decode([]byte(cert.Cert))
				if block == nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9207, "msg": fmt.Sprintf("Invalid certificate format for domain %s", domain)})
					return
				}
				certpem, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9208, "msg": fmt.Sprintf("Failed to parse certificate for domain %s", domain), "details": err.Error()})
					return
				}

				privBlock, _ := pem.Decode([]byte(cert.Key))
				if privBlock == nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9209, "msg": fmt.Sprintf("Invalid private key format for domain %s", domain)})
					return
				}

				var privateKey interface{}
				switch privBlock.Type {
				case "RSA PRIVATE KEY":
					privateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
				case "PRIVATE KEY":
					privateKey, err = x509.ParsePKCS8PrivateKey(privBlock.Bytes)
				default:
					c.JSON(http.StatusBadRequest, gin.H{"code": 9210, "msg": fmt.Sprintf("Unsupported private key format for domain %s", domain)})
					return
				}
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9211, "msg": fmt.Sprintf("Failed to parse private key for domain %s", domain), "details": err.Error()})
					return
				}

				password := ""
				pfxData, err := pkcs12.Legacy.Encode(privateKey, certpem, []*x509.Certificate{certpem}, password)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"code": 9212, "msg": fmt.Sprintf("Failed to encode PKCS#12 for domain %s", domain), "details": err.Error()})
					return
				}

				pfxAddress := config.Domains[domain].PfxAddress
				if pfxAddress == "" {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9213, "msg": fmt.Sprintf("PFX address is not configured for domain %s", domain)})
					return
				}

				if err := os.WriteFile(pfxAddress, pfxData, 0644); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"code": 9214, "msg": fmt.Sprintf("Failed to write PFX file for domain %s", domain), "details": err.Error()})
					return
				}
			}
		} else {
			for _, domain := range overlap {
				certAddress := config.Domains[domain].CertAddress
				if certAddress == "" {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9215, "msg": fmt.Sprintf("Certificate address is not configured for domain %s", domain)})
					return
				}

				keyAddress := config.Domains[domain].KeyAddress
				if keyAddress == "" {
					c.JSON(http.StatusBadRequest, gin.H{"code": 9216, "msg": fmt.Sprintf("Key address is not configured for domain %s", domain)})
					return
				}

				if err := os.WriteFile(certAddress, []byte(cert.Cert), 0644); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"code": 9217, "msg": fmt.Sprintf("Failed to write certificate file for domain %s", domain), "details": err.Error()})
					return
				}

				if err := os.WriteFile(keyAddress, []byte(cert.Key), 0644); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"code": 9218, "msg": fmt.Sprintf("Failed to write key file for domain %s", domain), "details": err.Error()})
					return
				}
			}
		}
		insertBind(bind.CertID, overlap)
		needreload = true
		c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "data": true})
	})
	r.POST("/reload", func(c *gin.Context) {
		var data map[string]interface{}
		if err := c.ShouldBindJSON(&data); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": 9200, "msg": err.Error()})
			return
		}
		headers := c.Request.Header
		if err := check_authorization(data, headers, "/reload"); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 9201, "msg": "Unauthorized", "details": err.Error()})
			return
		}
		if !needreload {
			c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "No changes detected, no reload needed"})
			return
		}
		// 执行 beforeexec 命令
		if config.BeforeExec != "" {
			if err := executeCommand(config.BeforeExec); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 9202, "msg": "Before exec command failed", "details": err.Error()})
				return
			}
		} else {
			log.Println("No beforeexec command configured, skipping.")
		}
		// 执行 reload 命令
		if config.AfterExec != "" {
			if err := executeCommand(config.AfterExec); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"code": 9203, "msg": "After exec command failed", "details": err.Error()})
				return
			}
		} else {
			log.Println("No afterexec command configured, skipping.")
		}
		needreload = false

		c.JSON(http.StatusOK, gin.H{"code": 200, "msg": "ok", "data": "Reload executed successfully"})
	})
	// 监听信号，优雅重启
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down server...")
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()

	// 启动服务
	log.Println("Starting server on :", config.Port)
	r.Run(":" + fmt.Sprint(config.Port))
}

// getNextCleanupTime 计算下一次清理任务的执行时间（每天 18:00）
func getNextCleanupTime() time.Time {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), 18, 0, 0, 0, now.Location())
	if now.After(next) {
		next = next.Add(24 * time.Hour) // 如果当前时间已经过了 18:00，则设置为明天的 18:00
	}
	return next
}

// cleanUpUnboundCertificates 清理未绑定的证书
func cleanUpUnboundCertificates(db *sql.DB) error {
	// 删除未被绑定的证书
	_, err := db.Exec(`
        DELETE FROM certificates
        WHERE id NOT IN (SELECT cert_id FROM bind);
    `)
	if err != nil {
		return fmt.Errorf("error deleting unbound certificates: %v", err)
	}

	fmt.Println("Unbound certificates cleaned up successfully")
	return nil
}

func validateDomain(certid float64, domains []string) bool {
	var i float64
	for _, domain := range domains {
		err := db.QueryRow("SELECT cert_id, domain FROM bind WHERE cert_id = ? AND domain = ?", certid, domain).Scan(&certid, &domain)
		if err != nil {
			if err == sql.ErrNoRows {
			} else {
				log.Printf("Error querying database: %v", err)
				return false
			}
		} else {
			// 找到对应的绑定关系
			i++
		}
	}
	if i == float64(len(domains)) {
		log.Printf("All domains are bound to the certificate with ID: %v", certid)
		return true
	} else {
		log.Printf("Not all domains are bound to the certificate with ID: %v", certid)
		return false
	}
}

func getOverlap(domain []interface{}, domains map[string]struct {
	CertAddress string `json:"cert"`
	KeyAddress  string `json:"key"`
	PfxAddress  string `json:"pfx"` // PFX 文件地址
}) []string {
	overlap := []string{}
	for _, d := range domain {
		if domainStr, ok := d.(string); ok {
			if _, exists := domains[domainStr]; exists {
				overlap = append(overlap, domainStr)
			}
		}
	}
	return overlap
}

func check_authorization(data map[string]interface{}, headers http.Header, path string) error {
	if headers.Get("x-accesskey") != config.AccessKey {
		return fmt.Errorf("invalid access key")
	}
	if headers.Get("x-path") != path {
		return fmt.Errorf("invalid path")
	}
	if headers.Get("x-timestamp") == "" {
		return fmt.Errorf("timestamp header error")
	}
	if headers.Get("x-app") != "allinssl" {
		return fmt.Errorf("invalid app header")
	}
	// 检查时间戳是否在允许的范围内
	timestamp := headers.Get("x-timestamp")
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %v", err)
	}

	// 使用 time.Unix 解析 Unix 时间戳
	t := time.Unix(ts, 0)
	now := time.Now() // 获取当前时间
	if now.After(t.Add(5*time.Minute)) || now.Before(t.Add(-5*time.Minute)) {
		return fmt.Errorf("timestamp is error, please check the timestamp")
	}
	// 检查签名
	if headers.Get("Authorization") == "" {
		return fmt.Errorf("authorization header is missing")
	}
	signature := headers.Get("Authorization")
	values := url.Values{}
	for k, v := range data {
		values.Add(k, fmt.Sprintf("%v", v))
	}
	values.Add("x-timestamp", timestamp)
	values.Add("x-app", headers.Get("x-app"))
	values.Add("x-accesskey", headers.Get("x-accesskey"))
	values.Add("x-path", headers.Get("x-path"))
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
	if !verifySignature(config.SecretKey, signStr, signature) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func createTable() {
	sqlStmt := `
    CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_name TEXT NOT NULL,
        cert TEXT NOT NULL,
        key TEXT NOT NULL
    );
	CREATE TABLE IF NOT EXISTS bind (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cert_id INTEGER NOT NULL,
        domain TEXT NOT NULL UNIQUE
    );
    `
	_, err := db.Exec(sqlStmt)
	if err != nil {
		log.Fatalf("Unable to create table: %v", err)
	}
}

func hmacSHA256(key, data string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// 定义一个函数来验证签名
func verifySignature(key, data, providedSignature string) bool {
	// 计算签名
	calculatedSignature := hmacSHA256(key, data)
	// 比较计算的签名和提供的签名
	return hmac.Equal([]byte(calculatedSignature), []byte(providedSignature))
}

func insertCert(cert Certificate) int {
	stmt, err := db.Prepare("INSERT INTO certificates (cert_name, cert, key) VALUES (?, ?, ?)")
	if err != nil {
		log.Fatalf("Unable to prepare statement: %v", err)
		return 0
	}
	defer stmt.Close()

	result, err := stmt.Exec(cert.CertName, cert.Cert, cert.Key)
	if err != nil {
		log.Fatalf("Unable to insert certificate: %v", err)
		return 0
	}
	lastID, err := result.LastInsertId()
	if err != nil {
		log.Fatalf("Unable to get last insert ID: %v", err)
		return 0
	}
	return int(lastID)
}

func insertBind(id float64, overlap []string) {
	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("Unable to start transaction: %v", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO bind (cert_id, domain) 
		VALUES (?, ?) 
		ON CONFLICT(domain) DO UPDATE SET cert_id=excluded.cert_id;
	`)
	if err != nil {
		log.Fatalf("Unable to prepare statement: %v", err)
	}
	defer stmt.Close()

	for _, domain := range overlap {
		_, err = stmt.Exec(id, domain)
		if err != nil {
			log.Fatalf("Unable to insert bind: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("Unable to commit transaction: %v", err)
	}
}
func loadConfig() error {
	// 定义默认的配置内容
	defaultConfig := map[string]interface{}{
		"port":       8090,
		"afterexec":  "",
		"if_iis":     false, // 是否为 IIS 服务器
		"beforeexec": "nginx -s reload",
		"domains": map[string]interface{}{
			"*.example.com": map[string]interface{}{
				"cert": "/path/to/cert.pem",
				"key":  "/path/to/key.pem",
				"pfx":  "/path/to/cert.pfx", // PFX 文件地址
			},
		},
		"accesskey": "your_access_key",
		"secretkey": "your_secret_key",
	}
	defaultConfigData, err := json.MarshalIndent(defaultConfig, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshaling default config: %v", err)
	}

	// 检查 config.json 文件是否存在
	if _, err := os.Stat("./config.json"); os.IsNotExist(err) {
		// 文件不存在，创建并写入默认配置
		err := os.WriteFile("./config.json", defaultConfigData, 0644)
		if err != nil {
			return fmt.Errorf("error writing config file: %v", err)
		}
		fmt.Println("Config file created with default content.")
	} else if err != nil {
		return fmt.Errorf("error checking config file: %v", err)
	} else {
		// 文件已存在，读取配置内容
		data, err := os.ReadFile("./config.json")
		if err != nil {
			return fmt.Errorf("unable to read config file: %v", err)
		}
		if len(data) == 0 {
			return fmt.Errorf("config file is empty, please check the content")
		}
		err = json.Unmarshal(data, &config)
		if err != nil {
			return fmt.Errorf("unable to unmarshal config file: %v", err)
		}
		if config.Port == 0 {
			return fmt.Errorf("port is not set in config file, please check the content")
		}
		if config.AccessKey == "" {
			return fmt.Errorf("accesskey is not set in config file, please check the content")
		}
		if config.SecretKey == "" {
			return fmt.Errorf("secretkey is not set in config file, please check the content")
		}
		if len(config.Domains) == 0 {
			return fmt.Errorf("domains are not set in config file, please check the content")
		}
		if len(config.BeforeExec) == 0 {
			return fmt.Errorf("beforeexec is not set in config file, please check the content")
		}
		fmt.Println("Config loaded successfully")
	}
	return nil
}

func watchConfigFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Unable to create watcher: %v", err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Println("Config file changed, reloading...")
					if err := loadConfig(); err != nil {
						log.Fatalf("Failed to reload config: %v", err)
						return
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("Error:", err)
			}
		}
	}()

	err = watcher.Add("./config.json")
	if err != nil {
		log.Fatalf("Unable to add file to watcher: %v", err)
	}
	<-done
}

func executeCommand(command string) error {
	var cmd *exec.Cmd

	// 根据操作系统选择合适的命令执行方式
	if runtime.GOOS == "windows" {
		// 在 Windows 上使用 cmd.exe 执行命令
		cmd = exec.Command("cmd", "/C", command)
	} else {
		// 在 Linux 和其他 Unix 系统上使用 sh 执行命令
		cmd = exec.Command("sh", "-c", command)
	}

	// 执行命令
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error executing command: %v", err)
	}
	return nil
}
