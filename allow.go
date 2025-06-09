package golangIPSentry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type AllowIPManager struct {
	Logger  *Logger
	Config  *Config
	Redis   *redis.Client
	Context context.Context
	Mutex   sync.RWMutex
	Cache   map[string]*IPItem
}

func (i *IPGuardian) newAllowManager() *AllowIPManager {
	manager := &AllowIPManager{
		Logger:  i.Logger,
		Config:  i.Config,
		Redis:   i.Redis,
		Context: i.Context,
		Cache:   make(map[string]*IPItem),
	}

	err := manager.load()
	if err != nil {
		i.Logger.Error(err, "Failed to load white list from file")
	}

	return manager
}

func (m *AllowIPManager) load() error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	path := defaultWhiteListPath
	// * custom path is exist, use it
	if m.Config.Filepath.WhiteList != "" {
		path = m.Config.Filepath.WhiteList
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

		key := fmt.Sprintf(redisAllow, item.IP)
		pipe.Set(m.Context, key, data, 0)
	}

	_, err = pipe.Exec(m.Context)
	// * failed to execute pipeline, stop importing
	if err != nil {
		return m.Logger.Error(err, "Failed to store white list to redis")
	}

	return nil
}

func (m *AllowIPManager) Check(ip string) bool {
	key := fmt.Sprintf(redisAllow, ip)
	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == nil && exist > 0 {
		return true
	}

	m.Mutex.RLock()
	defer m.Mutex.RUnlock()

	_, cache := m.Cache[ip]

	return cache
}

// * save white list to file
func (m *AllowIPManager) save() error {
	path := defaultWhiteListPath
	if m.Config.Filepath.WhiteList != "" {
		path = m.Config.Filepath.WhiteList
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

func (m *AllowIPManager) Add(ip string, tag string) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	item := &IPItem{
		IP:      ip,
		Reason:  tag,
		AddedAt: time.Now().UTC().Unix(),
	}

	m.Cache[ip] = item

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.Error(err, "Failed to parse white ip")
	}

	key := fmt.Sprintf(redisAllow, ip)
	if err := m.Redis.Set(m.Context, key, data, 0).Err(); err != nil {
		return m.Logger.Error(err, "Failed to store white ip to redis")
	}

	if err := m.save(); err != nil {
		return m.Logger.Error(err, "Failed to save white ip to file")
	}

	return nil
}
