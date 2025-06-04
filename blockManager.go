package golangIPGuardian

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type BlockItem struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	AddedAt int64  `json:"added_at"`
	Count   int    `json:"count"`
	Last    int64  `json:"last"`
}

type BlockManager struct {
	Logger    *Logger
	Config    *Config
	Redis     *redis.Client
	Context   context.Context
	Parameter *Parameter
}

func (i *IPGuardian) newBlockManager() *BlockManager {
	return &BlockManager{
		Logger:    i.Logger,
		Config:    i.Config,
		Redis:     i.Redis,
		Context:   i.Context,
		Parameter: &i.Config.Parameter,
	}
}

func (m *BlockManager) check(ip string) bool {
	key := fmt.Sprintf(redisBlock, ip)

	exist, err := m.Redis.Exists(m.Context, key).Result()
	if err == nil && exist > 0 {
		return true
	}

	return false
}

func (m *BlockManager) checkBlockItem(ip string) (bool, *BlockItem, error) {
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

	var item BlockItem
	if err := json.Unmarshal([]byte(data), &item); err != nil {
		return true, nil, err
	}

	return true, &item, nil
}

// * public
func (m *BlockManager) Add(ip string, reason string) error {
	key := fmt.Sprintf(redisBlock, ip)
	now := time.Now().Unix()

	var item *BlockItem

	isBlock, item, err := m.checkBlockItem(ip)
	if err != nil {
		return err
	}

	var duration time.Duration = time.Duration(m.Parameter.BlockTimeMin)

	if isBlock && item != nil {
		item.Reason += "\n" + reason
		item.Count++
		item.Last = now

		duration = time.Duration(1<<item.Count) * time.Duration(m.Parameter.BlockTimeMin) // * 指數增長封鎖時間
		if duration > time.Duration(m.Parameter.BlockTimeMax) {
			duration = time.Duration(m.Parameter.BlockTimeMax)
		}
	} else {
		item = &BlockItem{
			IP:      ip,
			Reason:  reason,
			AddedAt: now,
			Count:   1,
			Last:    now,
		}
	}

	data, err := json.Marshal(item)
	if err != nil {
		return m.Logger.error("Failed to parse block item", err.Error())
	}

	if err := m.Redis.Set(m.Context, key, data, duration).Err(); err != nil {
		return m.Logger.error("Failed to update block item in redis", err.Error())
	}

	return nil
}
