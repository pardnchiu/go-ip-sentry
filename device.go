// TODO 需花時間整理
package golangIPSentry

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

type Device struct {
	Platform    string
	Browser     string
	Type        string // * Desktop|Mobile|Tablet
	Is          IS
	OS          string
	IP          IP
	AcceptLang  string
	Referer     string
	SessionID   string
	Fingerprint string
}

type IS struct {
	Mobile   bool
	Tablet   bool
	Desktop  bool
	Internal bool
	Block    bool // * 是否被封鎖
	Ban      bool // * 是否在黑名單中
	Trust    bool // * 是否在白名單中
}

type IP struct {
	Address      string
	IsPrivate    bool
	Level        int
	RequestCount int
	BlockCount   int
}

func (i *IPGuardian) getDevice(w http.ResponseWriter, r *http.Request) (*Device, error) {
	userAgent := r.UserAgent()
	ipAddress, isPrivate, err := getClientIP(r)

	if err != nil {
		return nil, i.Logger.Error(nil, "Failed to get client IP")
	}

	ipTrustLevel := 0
	if isPrivate {
		ipTrustLevel = 1
	}

	deviceType := getType(userAgent)

	deviceInfo := &Device{
		Platform: getPlatform(userAgent),
		Browser:  getBrowser(userAgent),
		Type:     deviceType,
		Is: IS{
			Mobile:   deviceType == "Mobile",
			Tablet:   deviceType == "Tablet",
			Desktop:  deviceType == "Desktop",
			Internal: isPrivate,
			Trust:    i.Manager.Allow.Check(ipAddress),
			Ban:      i.Manager.Deny.Check(ipAddress),
			Block:    i.Manager.Block.IsBlock(ipAddress),
		},
		OS: getOS(userAgent),
		IP: IP{
			Address: ipAddress,
			Level:   ipTrustLevel,
		},
		AcceptLang: r.Header.Get("Accept-Language"),
		Referer:    r.Header.Get("Referer"),
	}

	requestCount, err := i.requestCountInMin(ipAddress)
	if err != nil {
		requestCount = 1
	}

	deviceInfo.IP.RequestCount = requestCount

	blockCount, err := i.blockCountInHour(ipAddress)
	if err != nil {
		blockCount = 0
	}
	deviceInfo.IP.BlockCount = blockCount

	sessionID, err := getSessionID(w, r, deviceInfo)
	if err != nil {
		return nil, err
	}
	deviceInfo.SessionID = sessionID

	fingerprint, err := getFingerprint(w, r, deviceInfo)
	if err != nil {
		return nil, err
	}
	deviceInfo.Fingerprint = fingerprint

	return deviceInfo, nil
}

func generateSessionID(length int) (string, error) {
	bytes := make([]byte, (length*3)/4+1)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	encoded := base64.URLEncoding.EncodeToString(bytes)
	encoded = strings.TrimRight(encoded, "=")

	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

func initSessionSecret() error {
	var err error
	secretOnce.Do(func() {
		sessionSecret, err = checkSessionSecret()
	})
	return err
}

func checkSessionSecret() (string, error) {
	const secretFile = ".sessionSecret"

	if _, err := os.Stat(secretFile); os.IsNotExist(err) {
		secret, err := uuid(128)
		if err != nil {
			return "", err
		}

		if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
			return "", err
		}

		return secret, nil
	} else if err != nil {
		return "", err
	}

	data, err := os.ReadFile(secretFile)
	if err != nil {
		return "", err
	}

	secret := strings.TrimSpace(string(data))

	if len(secret) <= 0 {
		newSecret, err := uuid(128)
		if err != nil {
			return "", err
		}

		if err := os.WriteFile(secretFile, []byte(newSecret), 0600); err != nil {
			return "", err
		}

		return newSecret, nil
	}

	return secret, nil
}

func getSessionSecret() (string, error) {
	if err := initSessionSecret(); err != nil {
		return "", err
	}
	return sessionSecret, nil
}

func signSessionID(sessionID string) (string, error) {
	secret, err := getSessionSecret()
	if err != nil {
		return "", err
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(sessionID))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return strings.TrimRight(signature, "="), nil
}

func verifySessionID(sessionID string, signature string) (bool, error) {
	expectedSig, err := signSessionID(sessionID)
	if err != nil {
		return false, err
	}
	return hmac.Equal([]byte(signature), []byte(expectedSig)), nil
}

func createSessionID() (string, error) {
	sessionID, err := generateSessionID(32)
	if err != nil {
		return "", err
	}

	signature, err := signSessionID(sessionID)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("s:%s.%s", sessionID, signature), nil
}

func parseSessionID(signed string) (string, bool) {
	if !strings.HasPrefix(signed, "s:") {
		return "", false
	}

	content := signed[2:]
	parts := strings.Split(content, ".")
	if len(parts) != 2 {
		return "", false
	}

	sessionID := parts[0]
	signature := parts[1]

	verify, err := verifySessionID(sessionID, signature)
	if err != nil || !verify {
		return "", false
	}

	return sessionID, true
}

func getSessionID(w http.ResponseWriter, r *http.Request, d *Device) (string, error) {
	cookie, err := r.Cookie(sessionKey)
	if err == nil && cookie.Value != "" {
		sessionID, valid := parseSessionID(cookie.Value)
		if valid {
			newCookie := &http.Cookie{
				Name:     sessionKey,
				Value:    cookie.Value,
				Path:     "/",
				MaxAge:   30 * 24 * 3600,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(w, newCookie)
			return sessionID, nil
		}
	}

	signedSessionID, err := createSessionID()
	if err != nil {
		return "", err
	}

	cookie = &http.Cookie{
		Name:     sessionKey,
		Value:    signedSessionID,
		Path:     "/",
		MaxAge:   30 * 24 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, cookie)

	sessionID, _ := parseSessionID(signedSessionID)
	return sessionID, nil
}

func getFingerprint(w http.ResponseWriter, r *http.Request, d *Device) (string, error) {
	key, err := uuid(128)
	if err != nil {
		return "", err
	}

	cookie, err := r.Cookie(deviceKey)
	if err == nil && cookie.Value != "" {
		key = cookie.Value
		newCookie := &http.Cookie{
			Name:     deviceKey,
			Value:    key,
			Path:     "/",
			MaxAge:   365 * 86400,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, newCookie)
	} else {
		cookie = &http.Cookie{
			Name:     deviceKey,
			Value:    key,
			Path:     "/",
			MaxAge:   365 * 86400,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		http.SetCookie(w, cookie)
	}

	info := fmt.Sprintf("%s/%s/%s/%s/%s",
		d.Platform,
		d.Browser,
		d.Type,
		d.OS,
		key,
	)

	hash := sha256.Sum256([]byte(info))

	return hex.EncodeToString(hash[:]), nil
}

func uuid(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	bytes := make([]byte, length)

	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}

func getClientIP(r *http.Request) (string, bool, error) {
	headers := []string{
		"CF-Connecting-IP",    // Cloudflare
		"X-Forwarded-For",     // 標準反向代理
		"X-Real-IP",           // Nginx
		"X-Client-IP",         // Apache
		"X-Cluster-Client-IP", // 叢集
		"X-Forwarded",         // 舊版本
		"Forwarded-For",       // 舊版本
		"Forwarded",           // 新標準
	}

	for _, header := range headers {
		if ip := r.Header.Get(header); ip != "" {
			if strings.Contains(ip, ",") {
				ip = strings.TrimSpace(strings.Split(ip, ",")[0])
			}
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip, isInternalIP(r), nil
			}
		}
	}

	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return ip, isInternalIP(r), nil
		}
	}

	if parsedIP := net.ParseIP(r.RemoteAddr); parsedIP != nil {
		return r.RemoteAddr, isInternalIP(r), nil
	}

	return "", false, fmt.Errorf("failed to parse client IP")
}

func getRemoteIP(r *http.Request) string {
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}
	return r.RemoteAddr
}

func isInternalIP(r *http.Request) bool {
	directIP := getRemoteIP(r)
	if directIP != "" && isInternal(directIP) {
		return true
	}

	if hasProxyHeader(r) {
		return checkProxy(r)
	}

	return false
}

func isInternal(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return isInternalIPRange(parsedIP)
}

func isInternalIPRange(ip net.IP) bool {
	for _, rangeStr := range internalIPs {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func hasProxyHeader(r *http.Request) bool {
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"CF-Connecting-IP",
		"X-Forwarded-Proto",
	}

	for _, header := range proxyHeaders {
		if r.Header.Get(header) != "" {
			return true
		}
	}
	return false
}

func checkProxy(r *http.Request) bool {
	directIP := getRemoteIP(r)
	if !isInternal(directIP) {
		return false
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return checkXFF(xff, directIP)
	}

	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return isInternal(realIP)
	}

	return false
}

func checkXFF(xff, proxyIP string) bool {
	ips := strings.Split(xff, ",")
	if len(ips) == 0 {
		return false
	}

	clientIP := strings.TrimSpace(ips[0])
	if !isInternal(clientIP) {
		return false
	}

	for idx := 1; idx < len(ips); idx++ {
		proxyInChain := strings.TrimSpace(ips[idx])
		if !isInternal(proxyInChain) {
			return false
		}
	}

	if len(ips) > 1 {
		lastProxy := strings.TrimSpace(ips[len(ips)-1])
		return lastProxy == proxyIP
	}

	return true
}

func getPlatform(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "android") {
		return "Android"
	}
	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		return "iOS"
	}
	if strings.Contains(ua, "windows") {
		return "Windows"
	}
	if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		return "macOS"
	}
	if strings.Contains(ua, "linux") {
		return "Linux"
	}

	return "Unknown"
}

func getBrowser(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edge") {
		return "Chrome"
	}
	if strings.Contains(ua, "firefox") {
		return "Firefox"
	}
	if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		return "Safari"
	}
	if strings.Contains(ua, "edge") {
		return "Edge"
	}
	if strings.Contains(ua, "opera") {
		return "Opera"
	}

	return "Unknown"
}

func getType(userAgent string) string {
	mobileRegex := regexp.MustCompile(`(?i)(mobile|phone|android|iphone|ipod|blackberry|webos)`)
	tabletRegex := regexp.MustCompile(`(?i)(tablet|ipad|kindle|silk)`)

	if mobileRegex.MatchString(userAgent) {
		return "Mobile"
	}
	if tabletRegex.MatchString(userAgent) {
		return "Tablet"
	}
	return "Desktop"
}

func getOS(userAgent string) string {
	ua := strings.ToLower(userAgent)

	if iosMatch := regexp.MustCompile(`os (\d+)_(\d+)`).FindStringSubmatch(ua); len(iosMatch) > 0 {
		return fmt.Sprintf("iOS %s.%s", iosMatch[1], iosMatch[2])
	}

	if androidMatch := regexp.MustCompile(`android (\d+\.?\d*)`).FindStringSubmatch(ua); len(androidMatch) > 0 {
		return fmt.Sprintf("Android %s", androidMatch[1])
	}

	if strings.Contains(ua, "windows nt 10.0") {
		return "Windows 10/11"
	}
	if strings.Contains(ua, "windows nt 6.3") {
		return "Windows 8.1"
	}
	if strings.Contains(ua, "windows nt 6.1") {
		return "Windows 7"
	}

	if macMatch := regexp.MustCompile(`mac os x (\d+)_(\d+)`).FindStringSubmatch(ua); len(macMatch) > 0 {
		return fmt.Sprintf("macOS %s.%s", macMatch[1], macMatch[2])
	}

	return getPlatform(userAgent)
}

func (i *IPGuardian) requestCountInMin(ip string) (int, error) {
	key := fmt.Sprintf(redisFrequency, ip, int64(math.Floor(float64(time.Now().UTC().Unix())/60)))

	count, err := i.Redis.Incr(i.Context, key).Result() // * 自動計數
	if err != nil {
		return 1, err
	}

	if count == 1 {
		i.Redis.Expire(i.Context, key, 2*time.Minute)
	}

	return int(count), nil
}

func (i *IPGuardian) blockCountInHour(ip string) (int, error) {
	if !i.Manager.Block.IsBlock(ip) {
		return 0, nil
	}

	key := fmt.Sprintf(redisBlockCount, ip)

	count, err := i.Redis.Incr(i.Context, key).Result() // * 自動計數
	if err != nil {
		return int(count), err
	}

	if count == 1 {
		i.Redis.Expire(i.Context, key, 1*time.Hour)
	}

	return int(count), nil
}
