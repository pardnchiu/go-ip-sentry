package golangIPSentry

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/redis/go-redis/v9"
)

type GeoLite2Config struct {
	CityDB    string `json:"city_db"`
	CountryDB string `json:"country_db"`
}

type GeoLite2 struct {
	Logger    *Logger
	Config    *Config
	Redis     *redis.Client
	Context   context.Context
	CityDB    *geoip2.Reader
	CountryDB *geoip2.Reader
	HighRisk  map[string]bool
}

type Location struct {
	Timestamp      int64   `json:"timestamp"`
	IP             string  `json:"ip"`
	Country        string  `json:"country"`
	CountryCode    string  `json:"country_code"`
	City           string  `json:"city"`
	Timezone       string  `json:"timezone"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	AccuracyRadius uint16  `json:"accuracy_radius"`
	IsDetail       bool    `json:"is_detail"`
}

func (i *IPGuardian) newGeoLite2() *GeoLite2 {
	checker := &GeoLite2{
		Logger:   i.Logger,
		Config:   i.Config,
		Redis:    i.Redis,
		Context:  i.Context,
		HighRisk: map[string]bool{},
	}

	if i.Config.Filepath.CityDB == "" && i.Config.Filepath.CountryDB == "" {
		return nil
	}

	cityDB, err := geoip2.Open(i.Config.Filepath.CityDB)
	if err != nil {
		i.Logger.WarnError(err, "Failed to load GeoLite2-City.mmdb")
	} else {
		checker.CityDB = cityDB
	}

	countryDB, err := geoip2.Open(i.Config.Filepath.CountryDB)
	if err != nil {
		i.Logger.Warn(err, "Failed to load GeoLite2-Country.mmdb")
	} else {
		checker.CountryDB = countryDB
	}

	if checker.CityDB == nil && checker.CountryDB == nil {
		return nil
	}

	return checker
}

func (c *GeoLite2) location(ip string) (*Location, error) {
	if c == nil {
		return &Location{
			IP: ip,
		}, fmt.Errorf("GeoCheck is not exist")
	}

	if isInternal(ip) {
		return &Location{
			IP: ip,
		}, nil
	}

	if location := c.get(ip); location != nil {
		return location, nil
	}

	location, err := c.query(ip)
	if err != nil {
		return &Location{
			IP: ip,
		}, err
	}

	location.IP = ip

	c.set(ip, location)

	return location, nil
}

func (c *GeoLite2) query(ip string) (*Location, error) {
	location := &Location{}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, c.Logger.Error(nil, "Invalid IP address format: "+ip)
	}

	if c.CityDB != nil {
		record, err := c.CityDB.City(parsedIP)
		if err == nil {
			location.Country = record.Country.Names["en"]
			location.CountryCode = record.Country.IsoCode
			location.City = record.City.Names["en"]

			if record.Location.TimeZone != "" {
				location.Timezone = record.Location.TimeZone
			}

			location.Latitude = float64(record.Location.Latitude)
			location.Longitude = float64(record.Location.Longitude)
			location.AccuracyRadius = record.Location.AccuracyRadius
			location.IsDetail = true

			return location, nil
		}
	}

	if c.CountryDB != nil {
		record, err := c.CountryDB.Country(parsedIP)
		if err == nil {
			location.Country = record.Country.Names["en"]
			location.CountryCode = record.Country.IsoCode

			return location, nil
		}
	}

	return nil, fmt.Errorf("IP not found in GeoLite2 database")
}

// * Get from redis
func (c *GeoLite2) get(ip string) *Location {
	key := fmt.Sprintf(redisGeoIP, ip)

	data, err := c.Redis.Get(c.Context, key).Result()
	if err != nil {
		return nil
	}

	var location Location
	if err := json.Unmarshal([]byte(data), &location); err != nil {
		return nil
	}

	return &location
}

// * Set to redis
func (c *GeoLite2) set(ip string, location *Location) {
	key := fmt.Sprintf(redisGeoIP, ip)

	data, err := json.Marshal(location)
	if err != nil {
		return
	}

	c.Redis.SetEx(c.Context, key, data, 24*time.Hour)
}

func (c *GeoLite2) close() {
	if c != nil {
		if c.CityDB != nil {
			c.CityDB.Close()
		}
		if c.CountryDB != nil {
			c.CountryDB.Close()
		}
	}
}

func (c *GeoLite2) risk(locations []string, flags *[]string, riskScore *RiskScore) error {
	if len(locations) == 0 {
		return nil
	}

	list := make([]Location, 0, len(locations))

	for _, loc := range locations {
		parts := strings.SplitN(loc, ":", 5)
		if len(parts) < 5 {
			continue
		}

		timestamp, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			continue
		}

		lat, err := strconv.ParseFloat(parts[3], 64)
		if err != nil {
			continue
		}

		lng, err := strconv.ParseFloat(parts[4], 64)
		if err != nil {
			continue
		}

		list = append(list, Location{
			Timestamp: timestamp,
			Country:   parts[1],
			City:      parts[2],
			Latitude:  lat,
			Longitude: lng,
		})
	}

	if len(list) == 0 {
		return nil
	}

	c.checkHighRisk(list, flags, riskScore)
	c.checkHopping(list, flags, riskScore)
	c.checkFrequentSwitch(list, flags, riskScore)
	c.checkRapidChange(list, flags, riskScore)

	return nil
}

func (c *GeoLite2) checkHighRisk(locations []Location, flags *[]string, riskScore *RiskScore) {
	list := make(map[string]bool)
	riskList := make(map[string]bool)
	for _, country := range c.Config.Parameter.HighRiskCountry {
		riskList[country] = true
	}

	for _, loc := range locations {
		if riskList[loc.CountryCode] {
			list[loc.Country] = true
		}
	}

	if c.Config.Parameter.ScoreGeoHighRisk <= 0 {
		c.Config.Parameter.ScoreGeoHighRisk = 30
	}

	if len(list) > 0 {
		*flags = append(*flags, "geo_high_risk")
		riskScore.Base += c.Config.Parameter.ScoreGeoHighRisk
		riskScore.Detail["geoCountries"] = len(list)
		riskScore.Detail["countries"] = getMapKeys(list)
	}
}

func (c *GeoLite2) checkHopping(locations []Location, flags *[]string, riskScore *RiskScore) {
	list := make(map[string]bool)

	for _, loc := range locations {
		if loc.Timestamp >= time.Now().UTC().UnixMilli()-3600000 {
			list[loc.Country] = true
		}
	}

	if c.Config.Parameter.ScoreGeoHopping <= 0 {
		c.Config.Parameter.ScoreGeoHopping = 15
	}

	// * 一小時內4個不同國家
	if len(list) > 4 {
		*flags = append(*flags, "geo_hopping")
		riskScore.Base += c.Config.Parameter.ScoreGeoHopping
		riskScore.Detail["geoCountries"] = len(list)
		riskScore.Detail["countries"] = getMapKeys(list)
	}
}

func (c *GeoLite2) checkFrequentSwitch(locations []Location, flags *[]string, riskScore *RiskScore) {
	var locationList []Location
	cityList := make(map[string]bool)

	for _, loc := range locations {
		if loc.Timestamp >= time.Now().UTC().UnixMilli()-3600000 {
			locationList = append(locationList, loc)
			cityList[loc.City] = true
		}
	}

	// * 一小時內4個不同城市
	if len(cityList) < 4 || len(locationList) < 5 {
		return
	}

	switchCount := 0
	for i := 1; i < len(locationList); i++ {
		if locationList[i].City != locationList[i-1].City {
			switchCount++
		}
	}

	if c.Config.Parameter.ScoreGeoFrequentSwitch <= 0 {
		c.Config.Parameter.ScoreGeoFrequentSwitch = 20
	}

	if switchCount > 4 {
		*flags = append(*flags, "geo_frequent_switching")
		riskScore.Base += c.Config.Parameter.ScoreGeoFrequentSwitch
		riskScore.Detail["geoSwitches"] = switchCount
		riskScore.Detail["switchCities"] = getMapKeys(cityList)
	}
}

func (c *GeoLite2) checkRapidChange(locations []Location, flags *[]string, riskScore *RiskScore) {
	if len(locations) < 2 {
		return
	}

	recent := locations[0]
	prev := locations[1]

	// * 只檢查1小時內
	timeDiff := recent.Timestamp - prev.Timestamp
	if timeDiff >= 3600000 {
		return
	}

	distance := calcDistance(prev.Latitude, prev.Longitude, recent.Latitude, recent.Longitude)
	hour := float64(timeDiff) / 3600000
	speed := distance / hour

	if c.Config.Parameter.ScoreGeoRapidChange <= 0 {
		c.Config.Parameter.ScoreGeoRapidChange = 25
	}
	// * 移動速度超過800公里/小時
	// * 距離超過500公里且在30分鐘內
	if speed > 800 || (distance > 500 && timeDiff < 1800000) {
		*flags = append(*flags, "rapid_geo_change")
		riskScore.Base += c.Config.Parameter.ScoreGeoRapidChange
		riskScore.Detail["rapidGeoChange"] = map[string]interface{}{
			"from":     fmt.Sprintf("%s:%s", prev.Country, prev.City),
			"to":       fmt.Sprintf("%s:%s", recent.Country, recent.City),
			"timeMs":   timeDiff,
			"distance": distance,
			"speed":    speed,
		}
	}
}

func calcDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	deltaLat := (lat2 - lat1) * math.Pi / 180
	deltaLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*
			math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}
