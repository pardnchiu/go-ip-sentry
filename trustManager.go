package golangIPGuardian

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type TrustItem struct {
	IP      string `json:"ip"`
	Tag     string `json:"tag"`
	AddedAt int64  `json:"added_at"`
}

type TrustManager struct {
	Logger    *Logger
	Config    *Config
	Redis     *redis.Client
	Context   context.Context
	Parameter *Parameter
	Mutex     sync.RWMutex
	Cache     map[string]*TrustItem
}

func (i *IPGuardian) newTrustManager() *TrustManager {
	manager := &TrustManager{
		Logger:    i.Logger,
		Config:    i.Config,
		Redis:     i.Redis,
		Context:   i.Context,
		Parameter: &i.Config.Parameter,
		Cache:     make(map[string]*TrustItem),
	}

	err := manager.load()
	if err != nil {
		i.Logger.error("Failed to load trust list from file", err.Error())
	}

	return manager
}

func (m *TrustManager) load() error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	path := ".trust.json"

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var list []TrustItem
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

		key := fmt.Sprintf(redisTrust, item.IP)
		pipe.Set(m.Context, key, data, 0)
	}

	_, err = pipe.Exec(m.Context)
	if err != nil {
		return m.Logger.error("Failed to load trust list to redis", err.Error())
	}

	return nil
}

func (m *TrustManager) check(ip string) bool {
	key := fmt.Sprintf(redisTrust, ip)
	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == nil && exist > 0 {
		return true
	}

	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	_, cache := m.Cache[ip]

	return cache
}

func (m *TrustManager) save() error {
	path := ".trust.json"

	var list []TrustItem
	for _, item := range m.Cache {
		list = append(list, *item)
	}

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// * public
func (m *TrustManager) Add(ip string, tag string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	item := &TrustItem{
		IP:      ip,
		Tag:     tag,
		AddedAt: time.Now().Unix(),
	}

	m.Cache[ip] = item

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.error("Failed to parse trust item", err.Error())
	}

	key := fmt.Sprintf(redisTrust, ip)
	if err := m.Redis.Set(m.Context, key, data, 0).Err(); err != nil {
		return m.Logger.error("Failed to save trust item to redis", err.Error())
	}

	if err := m.save(); err != nil {
		return m.Logger.error("Failed to save trust item to file", err.Error())
	}

	return nil
}
