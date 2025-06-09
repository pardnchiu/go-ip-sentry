package golangIPSentry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type DenyIPManager struct {
	Logger  *Logger
	Config  *Config
	Redis   *redis.Client
	Context context.Context
	Mutex   sync.RWMutex
	Cache   map[string]*IPItem
}

func (i *IPGuardian) newDenyIPManager() *DenyIPManager {
	manager := &DenyIPManager{
		Logger:  i.Logger,
		Config:  i.Config,
		Redis:   i.Redis,
		Context: i.Context,
		Cache:   make(map[string]*IPItem),
	}

	err := manager.load()
	if err != nil {
		i.Logger.Error(err, "Failed to load black list from file")
	}

	return manager
}

func (m *DenyIPManager) load() error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	path := defaultBlackListPath
	// * custom path is exist, use it
	if m.Config.Filepath.BlackList != "" {
		path = m.Config.Filepath.BlackList
	}

	// * file is not exist, skip importing
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	// * failed to read file, stop importing
	if err != nil {
		return err
	}

	var list []IPItem
	// * failed to parse json, stop importing
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	pipe := m.Redis.Pipeline()

	for _, item := range list {
		data, err := json.Marshal(item)
		// * failed to parse item, skip this item
		if err != nil {
			continue
		}
		// * add item to memory cache
		m.Cache[item.IP] = &item

		key := fmt.Sprintf(redisDeny, item.IP)
		pipe.Set(m.Context, key, data, 0)
	}

	_, err = pipe.Exec(m.Context)
	// * failed to execute pipeline, stop importing
	if err != nil {
		return m.Logger.Error(err, "Failed to store black list to redis")
	}

	return nil
}

func (m *DenyIPManager) Check(ip string) bool {
	key := fmt.Sprintf(redisDeny, ip)
	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == nil && exist > 0 {
		return true
	}

	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	_, cache := m.Cache[ip]

	return cache
}

// * save black list to file
func (m *DenyIPManager) save() error {
	path := defaultBlackListPath
	if m.Config.Filepath.BlackList != "" {
		path = m.Config.Filepath.BlackList
	}

	var list []IPItem
	for _, item := range m.Cache {
		list = append(list, *item)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (m *DenyIPManager) sendEmail(ip string, reason string) {
	if m.Config.Email == nil {
		return
	}

	subject := fmt.Sprintf("[IP Sentry] IP %s has been banned", ip)
	if m.Config.Email.Subject != nil {
		str := (*m.Config.Email.Subject)(ip, reason)
		if str != "" {
			subject = str
		}
	}
	body := fmt.Sprintf("[IP Sentry] IP %s has been banned for %s", ip, reason)
	if m.Config.Email.Body != nil {
		str := (*m.Config.Email.Body)(ip, reason)
		if str != "" {
			body = str
		}
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nCc: %s\r\nSubject: %s\r\n\r\n%s",
		m.Config.Email.From,
		strings.Join(m.Config.Email.To, ","),
		strings.Join(m.Config.Email.CC, ","),
		subject,
		body)

	auth := smtp.PlainAuth("", m.Config.Email.Username, m.Config.Email.Password, m.Config.Email.Host)
	addr := fmt.Sprintf("%s:%d", m.Config.Email.Host, m.Config.Email.Port)

	err := smtp.SendMail(addr, auth, m.Config.Email.From, m.Config.Email.To, []byte(msg))
	if err != nil {
		m.Logger.Error(err, "Failed to send email")
	}
}

// * public
func (m *DenyIPManager) Add(ip, reason string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	item := &IPItem{
		IP:      ip,
		Reason:  reason,
		AddedAt: time.Now().UTC().Unix(),
	}

	m.Cache[ip] = item

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.Error(err, "Failed to parse black ip")
	}

	key := fmt.Sprintf(redisDeny, ip)
	if err := m.Redis.Set(m.Context, key, data, 0).Err(); err != nil {
		return m.Logger.Error(err, "Failed to store black ip to redis")
	}

	if err := m.save(); err != nil {
		return m.Logger.Error(err, "Failed to save black ip to file")
	}

	if m.Config != nil {
		go m.sendEmail(ip, reason)
	}

	return nil
}
