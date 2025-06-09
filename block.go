package golangIPSentry

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type BlockIPManager struct {
	Logger  *Logger
	Config  *Config
	Redis   *redis.Client
	Context context.Context
}

func (i *IPGuardian) newBlocIPkManager() *BlockIPManager {
	return &BlockIPManager{
		Logger:  i.Logger,
		Config:  i.Config,
		Redis:   i.Redis,
		Context: i.Context,
	}
}

func (m *BlockIPManager) IsBlock(ip string) bool {
	key := fmt.Sprintf(redisBlock, ip)

	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == redis.Nil {
		return false
	}

	if exist > 0 {
		return true
	}

	return false
}

func (m *BlockIPManager) checkBlockIP(ip string) (bool, *IPItem, error) {
	key := fmt.Sprintf(redisBlock, ip)

	exists, err := m.Redis.Exists(m.Context, key).Result()
	if err != nil {
		return false, nil, err
	}

	if exists == 0 {
		return false, nil, nil
	}

	data, err := m.Redis.Get(m.Context, key).Result()
	if err != nil {
		return true, nil, err
	}

	var item IPItem
	if err := json.Unmarshal([]byte(data), &item); err != nil {
		return true, nil, err
	}

	return true, &item, nil
}

// * public
func (m *BlockIPManager) Add(ip string, reason string) error {
	key := fmt.Sprintf(redisBlock, ip)
	now := time.Now().UTC().Unix()

	var item *IPItem

	isBlock, item, err := m.checkBlockIP(ip)
	if err != nil {
		return err
	}

	var duration time.Duration = time.Duration(m.Config.Parameter.BlockTimeMin) // 默認封鎖時間

	if isBlock && item != nil {
		item.Reason += "\n" + reason
		item.Count++
		item.Last = now

		duration = time.Duration(1<<item.Count) * time.Duration(m.Config.Parameter.BlockTimeMin) // * 指數增長封鎖時間
		if duration > time.Duration(m.Config.Parameter.BlockTimeMax) {
			duration = time.Duration(m.Config.Parameter.BlockTimeMax)
		}
	} else {
		item = &IPItem{
			IP:      ip,
			Reason:  reason,
			AddedAt: now,
			Count:   1,
			Last:    now,
		}
	}

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.Error(err, "Failed to parse block item")
	}

	if err := m.Redis.Set(m.Context, key, data, duration).Err(); err != nil {
		return m.Logger.Error(err, "Failed to update block item in redis")
	}

	return nil
}
