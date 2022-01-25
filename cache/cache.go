package cache

import (
	"container/list"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// const maxCacheSize = 10_000

type cacheItem struct {
	msg     *dns.Msg
	addedAt time.Time
	ttl     time.Duration
	elem    *list.Element
}

type cacheKey struct {
	addr string
	q    dns.Question
}

type Cache struct {
	maxSize int
	mu      sync.Mutex
	cache   map[cacheKey]cacheItem
	lru     *list.List // list of cacheKey
}

func New(maxSize int) *Cache {
	return &Cache{
		maxSize: maxSize,
		cache:   map[cacheKey]cacheItem{},
		lru:     list.New(),
	}
}

func (c *Cache) Clear() {
	c.mu.Lock()
	c.cache = map[cacheKey]cacheItem{}
	c.lru.Init()
	c.mu.Unlock()
}

func (c *Cache) Lookup(q dns.Question, addr string) (*dns.Msg, time.Duration, time.Duration) {
	now := time.Now()

	key := cacheKey{
		addr: addr,
		q:    q,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ci, ok := c.cache[key]
	if !ok {
		return nil, 0, -1 * time.Second
	}

	if ci.addedAt.Add(ci.ttl).Before(now) {
		c.lru.Remove(ci.elem)
		delete(c.cache, key)

		return nil, 0, -1 * time.Second
	}

	c.lru.MoveToBack(ci.elem)

	return ci.msg.Copy(), time.Since(now), time.Since(ci.addedAt)
}

func (c *Cache) Update(q dns.Question, addr string, resp *dns.Msg, ttl time.Duration) {
	if resp == nil {
		panic("nil response")
	}

	key := cacheKey{
		addr: addr,
		q:    q,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ci := c.cache[key]
	ci.msg = resp.Copy()
	ci.addedAt = time.Now()
	ci.ttl = ttl
	if ci.elem == nil {
		ci.elem = c.lru.PushBack(key)
	} else {
		c.lru.MoveToBack(ci.elem)
	}

	c.cache[key] = ci

	c.prune()

	if c.lru.Len() != len(c.cache) {
		panic(fmt.Sprintf("map and list out of sync: len(map)=%d, len(list)=%d", len(c.cache), c.lru.Len()))
	}
}

func (c *Cache) prune() {
	for len(c.cache) > c.maxSize {
		elem := c.lru.Front()
		key := elem.Value.(cacheKey)

		delete(c.cache, key)
		c.lru.Remove(elem)
	}
}
