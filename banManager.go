package golangIPGuardian

import (
	"context"
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type BanItem struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	AddedAt int64  `json:"added_at"`
}

type BanManager struct {
	Logger    *Logger
	Config    *Config
	Redis     *redis.Client
	Context   context.Context
	Parameter *Parameter
	Mutex     sync.RWMutex
	Cache     map[string]*BanItem
}

func (i *IPGuardian) newBanManager() *BanManager {
	manager := &BanManager{
		Logger:    i.Logger,
		Config:    i.Config,
		Redis:     i.Redis,
		Context:   i.Context,
		Parameter: &i.Config.Parameter,
		Cache:     make(map[string]*BanItem),
	}

	err := manager.load()
	if err != nil {
		i.Logger.error("Failed to load ban list from file", err.Error())
	}

	return manager
}

func (m *BanManager) load() error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	path := ".ban.json"

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var list []BanItem
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}

	pipe := m.Redis.Pipeline()

	for _, item := range list {
		m.Cache[item.IP] = &item

		data, err := json.Marshal(item)
		if err != nil {
			continue
		}

		key := fmt.Sprintf(redisBan, item.IP)
		pipe.Set(m.Context, key, data, 0)
	}

	_, err = pipe.Exec(m.Context)
	if err != nil {
		return m.Logger.error("Failed to load ban list to redis", err.Error())
	}

	return nil
}

func (m *BanManager) check(ip string) bool {
	key := fmt.Sprintf(redisBan, ip)
	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == nil && exist > 0 {
		return true
	}

	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	_, cache := m.Cache[ip]

	return cache
}

func (m *BanManager) save() error {
	path := ".ban.json"

	var list []BanItem
	for _, item := range m.Cache {
		list = append(list, *item)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func (m *BanManager) sendEmail(ip string, reason string) {
	if m.Config.Email == nil {
		return
	}

	subject := fmt.Sprintf("[IP Guardian] IP %s has been blacklisted", ip)
	body := ""
	msg := fmt.Sprintf("Subject: %s\r\n\r\n%s", subject, body)

	auth := smtp.PlainAuth("", m.Config.Email.Username, m.Config.Email.Password, m.Config.Email.Host)
	addr := fmt.Sprintf("%s:%d", m.Config.Email.Host, m.Config.Email.Port)

	err := smtp.SendMail(addr, auth, m.Config.Email.From, m.Config.Email.To, []byte(msg))
	if err != nil {
		m.Logger.error("Failed to send email", err.Error())
	}
}

// * public
func (m *BanManager) Add(ip, reason string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	item := &BanItem{
		IP:      ip,
		Reason:  reason,
		AddedAt: time.Now().Unix(),
	}

	m.Cache[ip] = item

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.error("Failed to parse ban item", err.Error())
	}

	key := fmt.Sprintf(redisBan, ip)
	if err := m.Redis.Set(m.Context, key, data, 0).Err(); err != nil {
		return m.Logger.error("Failed to save ban item to redis", err.Error())
	}

	if err := m.save(); err != nil {
		return m.Logger.error("Failed to save ban item to file", err.Error())
	}

	if m.Config != nil {
		go m.sendEmail(ip, reason)
	}

	return nil
}
