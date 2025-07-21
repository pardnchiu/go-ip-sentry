# go-ip-sentry - Architecture

Last updated: 2026-10-05

> Back to [README](../README.md)

## Overview

```mermaid
graph TB
    REQ[HTTP Request] --> MW[Middleware<br/>GinMiddleware / HTTPMiddleware]
    MW --> CHK[IPGuardian.Check]
    CHK --> DEV[Device Identification<br/>getDevice]
    DEV --> MGR[List Management<br/>Allow / Deny / Block]
    CHK --> SCORE[Dynamic Scoring<br/>dynamicScore]
    SCORE --> BASIC[Correlation]
    SCORE --> GEOS[Geo]
    SCORE --> BEH[Behavior]
    SCORE --> FP[Fingerprint]
    GEOS --> GEO[GeoLite2]
    BASIC & GEOS & BEH & FP & MGR & DEV <--> REDIS[(Redis)]
    MGR --> FILE[(List JSON Files)]
    MGR --> SMTP[SMTP Notification]
    CHK --> RES[IPGuardianResult]
```

## Module: Instance

Creates the instance, applies defaults, and wires the check flow.

```mermaid
graph TB
    subgraph Instance
        NEW[New] --> LOG[validLoggerConfig<br/>go-logger]
        NEW --> RC[redis.NewClient + PING]
        NEW --> MAN[Manager<br/>Allow / Deny / Block]
        NEW --> G2[newGeoLite2]
        CHK[Check] --> DEFAULTS[Rate Limit Defaults]
        CHK --> DS[dynamicScore]
        CLOSE[Close] --> RC
        CLOSE --> G2
        CLOSE --> LOG
    end
    CFG[Config] --> NEW
    MW[Middleware] --> CHK
```

```mermaid
classDiagram
    class IPGuardian {
        +Context context.Context
        +Config *Config
        +Redis *redis.Client
        +Logger *Logger
        +GeoLite2 *GeoLite2
        +Manager *Manager
        +Check(r, w) IPGuardianResult
        +GinMiddleware() gin.HandlerFunc
        +HTTPMiddleware(next) http.Handler
        +LoginFailure(w, r) error
        +NotFound404(w, r) error
        +Close() error
    }
    class Manager {
        +Allow *AllowIPManager
        +Block *BlockIPManager
        +Deny *DenyIPManager
    }
    class Config {
        +Redis Redis
        +Email *EmailConfig
        +Log *Log
        +Filepath Filepath
        +Parameter Parameter
    }
    class IPGuardianResult {
        +Success bool
        +StatusCode int
        +Error string
    }
    IPGuardian --> Manager
    IPGuardian --> Config
    IPGuardian ..> IPGuardianResult
```

## Module: Device

Resolves the client IP, User-Agent, session, and device fingerprint from the request, and attaches list status and counters.

```mermaid
graph TB
    subgraph Device
        GD[getDevice] --> IP[getClientIP<br/>Proxy Headers → RemoteAddr]
        IP --> INT[isInternalIP<br/>Private CIDR Check]
        GD --> UA[UA Parsing<br/>Platform / Browser / Type / OS]
        GD --> FLAGS[List Status<br/>Trust / Ban / Block]
        GD --> RCNT[requestCountInMin]
        GD --> BCNT[blockCountInHour]
        GD --> SID[getSessionID]
        SID --> SIGN[HMAC-SHA256 Signature<br/>s:id.sig]
        SIGN --> SEC[.sessionSecret]
        GD --> FPR[getFingerprint<br/>SHA-256 of UA + Device Cookie]
    end
    REQ[http.Request] --> GD
    SID --> CK1[Cookie conn.sess.id]
    FPR --> CK2[Cookie conn.device.id]
    RCNT --> REDIS[(Redis)]
    BCNT --> REDIS
    FLAGS --> MGR[Manager]
```

## Module: Score

Four dimensions run in parallel goroutines, each accumulating its own score before a mutex-guarded merge.

```mermaid
graph TB
    subgraph Score
        DS[dynamicScore] --> CB[calcBasic]
        DS --> CG[calcGeo]
        DS --> CBH[calcBehavior]
        DS --> CF[calcFingerprint]
        CB --> MERGE[Merge Flags / Detail]
        CG --> MERGE
        CBH --> MERGE
        CF --> MERGE
        MERGE --> CS[calcScore<br/>+25 when Detail > 4, cap 100]
        CS --> ITEM[ScoreItem<br/>IsBlock / IsSuspicious / IsDangerous]
    end
    CB --> R1[Session↔IP / IP↔Device / Device↔IP<br/>Login Failure / 404]
    CBH --> R2[Request Interval Variance<br/>Session Duration]
    CF --> R3[Sessions per Fingerprint per Minute]
    CG --> GEO[GeoLite2.risk]
    R1 & R2 & R3 --> REDIS[(Redis)]
```

## Module: GeoLite2

Looks up and caches IP locations, then evaluates geo risk from the last 10 location records.

```mermaid
graph TB
    subgraph GeoLite2
        LOC[location] --> INTL{Internal IP?}
        INTL -->|Yes| EMPTY[Empty Location]
        INTL -->|No| GET[get<br/>Redis Cache]
        GET -->|Miss| Q[query]
        Q --> CITY[CityDB.City]
        Q -->|City fails| COUNTRY[CountryDB.Country]
        Q --> SET[set<br/>Cache 24 h]
        RISK[risk] --> HR[checkHighRisk]
        RISK --> HOP[checkHopping<br/>> 4 countries in 1 h]
        RISK --> SW[checkFrequentSwitch<br/>> 4 city switches]
        RISK --> RAPID[checkRapidChange<br/>Haversine speed > 800]
    end
    CG[calcGeo] --> LOC
    CG --> HIST[geo:locations last 10]
    HIST --> RISK
    MMDB[(GeoLite2 mmdb)] --> CITY
    MMDB --> COUNTRY
```

## Module: Manager

Three-tier lists: Allow and Deny are permanent and persisted to files; Block is a temporary ban with a TTL.

```mermaid
graph TB
    subgraph Manager
        subgraph Allow
            AL[load] --> AC[(Memory Cache)]
            AA[Add] --> AC
            AA --> AS[save]
            ACK[Check]
        end
        subgraph Deny
            DL[load] --> DC[(Memory Cache)]
            DA[Add] --> DC
            DA --> DSV[save]
            DA --> MAIL[sendEmail<br/>goroutine]
            DCK[Check]
        end
        subgraph Block
            BA[Add] --> CHKB[checkBlockIP]
            CHKB --> TTL[Duration = 2^count × BlockTimeMin<br/>cap BlockTimeMax]
            BIS[IsBlock]
        end
    end
    AF[(whiteList.json)] --> AL
    AS --> AF
    DF[(blackList.json)] --> DL
    DSV --> DF
    AA & ACK & DA & DCK & TTL & BIS <--> REDIS[(Redis)]
    MAIL --> SMTP[SMTP]
```

## Data Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant MW as Middleware
    participant G as IPGuardian
    participant D as Device
    participant M as Manager
    participant S as Score
    participant R as Redis
    participant H as Downstream Handler

    C->>MW: HTTP request
    MW->>G: Check(r, w)
    G->>D: getDevice
    D->>M: Allow / Deny / Block status
    M->>R: EXISTS allow / deny / block
    D->>R: INCR frequency:{ip}:{minute}
    D-->>C: Set-Cookie session / device
    D-->>G: Device
    alt Trust
        G-->>MW: 200
    else Block / Ban
        G-->>MW: 403
    else Unlisted
        par Four dimensions
            G->>S: calcBasic
            G->>S: calcGeo
            G->>S: calcBehavior
            G->>S: calcFingerprint
        end
        S->>R: Pipeline read/write
        S-->>G: ScoreItem
        alt Score ≥ 100 or over tier rate limit
            G-->>MW: 403
        else
            G-->>MW: 200
        end
    end
    alt Success
        MW->>H: next
        H-->>C: Response
    else Failure
        MW-->>C: JSON error
    end
```

## State Machine

State of a single IP within the Check flow.

```mermaid
stateDiagram-v2
    [*] --> Unlisted
    Unlisted --> Trusted: Allow.Add
    Unlisted --> Blocked: Block.Add
    Unlisted --> Denied: Deny.Add
    Blocked --> Blocked: Block.Add (count +1, duration doubles)
    Blocked --> Unlisted: TTL expires
    Blocked --> Denied: Deny.Add
    Unlisted --> Normal: score < ScoreSuspicious
    Unlisted --> Suspicious: score ≥ ScoreSuspicious
    Unlisted --> Dangerous: score ≥ ScoreDangerous
    Normal --> Unlisted: rescored on next request
    Suspicious --> Unlisted: rescored on next request
    Dangerous --> Unlisted: rescored on next request
    Trusted --> [*]
    Denied --> [*]
```

***

©️ 2025 [邱敬幃 Pardn Chiu](https://www.linkedin.com/in/pardnchiu)
