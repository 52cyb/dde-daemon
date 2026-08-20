// SPDX-FileCopyrightText: 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

package accounts

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/linuxdeepin/go-lib/utils"
)

const (
	sqLimitStateFile = "/var/lib/dde-daemon/sq-limit-states.json"
)

// 安全问题验证的默认限制参数
const (
	sqDefaultMaxRetries = 10  // 默认最大尝试次数
	sqDefaultLockSecs   = 300 // 默认锁定时间（秒），5 分钟

	// 参数合法范围（与 DConfig JSON 描述一致）
	sqMaxRetriesMin = 1      // 最小尝试次数
	sqMaxRetriesMax = 100    // 最大尝试次数上限
	sqLockSecsMin   = 60     // 最小锁定时间（1分钟）
	sqLockSecsMax   = 604800 // 最大锁定时间（7天），确保 Duration 不溢出

	sqMaxFailuresCap = 100 // 失败计数器饱和上限（等于 maxRetries 最大值，防止 int 溢出）
)

// sqLimitState 单个用户的安全问题限制状态
type sqLimitState struct {
	NumFailures int       `json:"numFailures"`
	LockAt      time.Time `json:"lockAt"`
}

// sqLimitManager 管理所有用户的安全问题限制状态
type sqLimitManager struct {
	mu         sync.Mutex
	states     map[string]*sqLimitState // key: username
	maxRetries int
	lockSecs   int
}

var globalSqLimitManager = &sqLimitManager{
	states:     make(map[string]*sqLimitState),
	maxRetries: sqDefaultMaxRetries,
	lockSecs:   sqDefaultLockSecs,
}

func init() {
	globalSqLimitManager.loadStates()
}

// SetSqLimitParams 设置安全问题限制参数，含极值校验
// 超出合法范围的参数值（sqMaxRetries: 1~100, sqLockSecs: 60~604800）
// 会自动回退为默认值（10次/300秒），并记录警告日志
func SetSqLimitParams(maxRetries, lockSecs int) {
	globalSqLimitManager.mu.Lock()
	defer globalSqLimitManager.mu.Unlock()

	// sqMaxRetries 校验：超出合法范围则回退默认值
	if maxRetries < sqMaxRetriesMin || maxRetries > sqMaxRetriesMax {
		logger.Warningf("[sqLimit] sqMaxRetries %d out of range [%d, %d], use default %d",
			maxRetries, sqMaxRetriesMin, sqMaxRetriesMax, sqDefaultMaxRetries)
		maxRetries = sqDefaultMaxRetries
	}
	globalSqLimitManager.maxRetries = maxRetries

	// sqLockSecs 校验：超出合法范围则回退默认值
	if lockSecs < sqLockSecsMin || lockSecs > sqLockSecsMax {
		logger.Warningf("[sqLimit] sqLockSecs %d out of range [%d, %d], use default %d",
			lockSecs, sqLockSecsMin, sqLockSecsMax, sqDefaultLockSecs)
		lockSecs = sqDefaultLockSecs
	}
	globalSqLimitManager.lockSecs = lockSecs
}

// sqAllow 检查该用户的安全问题验证是否被允许
func sqAllow(username string) bool {
	return globalSqLimitManager.allow(username)
}

// sqFail 记录一次安全问题验证失败
func sqFail(username string) {
	globalSqLimitManager.fail(username)
}

// sqReset 重置该用户的安全问题限制（密码重置成功后调用）
func sqReset(username string) {
	globalSqLimitManager.reset(username)
}

// sqGetLimits 获取该用户的限制状态信息
func sqGetLimits(username string) (locked bool, maxTries int, numFailures int, unlockTime time.Time) {
	return globalSqLimitManager.getLimits(username)
}

func (m *sqLimitManager) getState(username string) *sqLimitState {
	s, ok := m.states[username]
	if !ok {
		s = &sqLimitState{}
		m.states[username] = s
	}
	// 防御性校验：防止状态文件篡改导致 NumFailures 为负，绕过 allow() 锁定检查
	if s.NumFailures < 0 || s.NumFailures > sqMaxFailuresCap {
		logger.Warningf("[sqLimit] invalid NumFailures %d for user %s, reset to 0",
			s.NumFailures, username)
		s.NumFailures = 0
	}
	return s
}

func (m *sqLimitManager) allow(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.getState(username)
	if s.NumFailures < m.maxRetries {
		return true
	}
	// 防御性检查：NumFailures >= maxRetries 但 LockAt 为零值时，自动补设锁定时间
	if s.LockAt.IsZero() {
		s.LockAt = time.Now()
		m.saveStates()
	}
	// 防御性检查：lockSecs 异常时（<=0），使用默认值防止 Duration 计算异常
	lockSecs := m.lockSecs
	if lockSecs <= 0 {
		lockSecs = sqDefaultLockSecs
	}
	// 检查锁定是否已过期
	if !s.LockAt.IsZero() && time.Since(s.LockAt) >= time.Duration(lockSecs)*time.Second {
		// 锁定已过期，重置
		logger.Warningf("[sqLimit] lock expired for user=%s, resetting", username)
		s.NumFailures = 0
		s.LockAt = time.Time{}
		m.saveStates()
		return true
	}
	logger.Warningf("[sqLimit] verification denied, user=%s locked, failures=%d, maxRetries=%d", username, s.NumFailures, m.maxRetries)
	return false
}

func (m *sqLimitManager) fail(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.getState(username)
	s.NumFailures++
	// 计数器饱和保护：防止 int 溢出回绕后绕过 allow() 检查
	if s.NumFailures > sqMaxFailuresCap {
		s.NumFailures = sqMaxFailuresCap
	}
	if s.NumFailures >= m.maxRetries {
		s.LockAt = time.Now()
		logger.Warningf("[sqLimit] user=%s reached max retries (%d), locked until %v", username, m.maxRetries, s.LockAt)
	}
	m.saveStates()
}

func (m *sqLimitManager) reset(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.states[username]; ok {
		s.NumFailures = 0
		s.LockAt = time.Time{}
		logger.Warningf("[sqLimit] reset limits for user=%s", username)
		m.saveStates()
	}
}

func (m *sqLimitManager) getLimits(username string) (locked bool, maxTries int, numFailures int, unlockTime time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.getState(username)
	maxTries = m.maxRetries

	if s.NumFailures >= m.maxRetries && !s.LockAt.IsZero() {
		// 防御性检查：lockSecs 异常时使用默认值
		lockSecs := m.lockSecs
		if lockSecs <= 0 {
			lockSecs = sqDefaultLockSecs
		}
		elapsed := time.Since(s.LockAt)
		lockDuration := time.Duration(lockSecs) * time.Second
		if elapsed < lockDuration {
			locked = true
			unlockTime = s.LockAt.Add(lockDuration)
			numFailures = s.NumFailures
		} else {
			// 锁定已过期，重置计数
			s.NumFailures = 0
			s.LockAt = time.Time{}
			m.saveStates()
			numFailures = 0
		}
	} else {
		numFailures = s.NumFailures
	}
	return
}

func (m *sqLimitManager) loadStates() {
	data, err := os.ReadFile(sqLimitStateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warningf("[sqLimit] load states failed: %v", err)
		}
		return
	}
	var states map[string]*sqLimitState
	if err := json.Unmarshal(data, &states); err != nil {
		logger.Warningf("[sqLimit] unmarshal states failed: %v", err)
		return
	}
	// 加载时校验：修复状态文件中可能存在的异常值（文件篡改或旧版本遗留数据）
	for username, s := range states {
		if s.NumFailures < 0 || s.NumFailures > sqMaxFailuresCap {
			logger.Warningf("[sqLimit] load: invalid NumFailures %d for %s, reset to 0",
				s.NumFailures, username)
			s.NumFailures = 0
		}
	}
	m.states = states
}

func (m *sqLimitManager) saveStates() {
	data, err := json.Marshal(m.states)
	if err != nil {
		logger.Warningf("[sqLimit] marshal states failed: %v", err)
		return
	}
	if err := utils.SyncWriteFile(sqLimitStateFile, data, 0600); err != nil {
		logger.Warningf("[sqLimit] save states failed: %v", err)
	}
}
