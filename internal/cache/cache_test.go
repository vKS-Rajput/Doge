package cache

import (
	"fmt"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Len() != 0 {
		t.Errorf("new cache Len() = %d, want 0", c.Len())
	}
}

func TestNew_DefaultMaxEntries(t *testing.T) {
	c := New(Options{MaxEntries: 0})
	if c.maxEntries != 1000 {
		t.Errorf("maxEntries = %d, want 1000 (default)", c.maxEntries)
	}
}

func TestGetSet(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	c.Set("key1", "value1")

	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected key1 to exist")
	}
	if val != "value1" {
		t.Errorf("Get(key1) = %v, want 'value1'", val)
	}
}

func TestGet_Miss(t *testing.T) {
	c := New(Options{MaxEntries: 100})

	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected miss for nonexistent key")
	}
}

func TestGet_Expired(t *testing.T) {
	c := New(Options{MaxEntries: 100})

	// Set with a very short TTL.
	c.SetWithTTL("ephemeral", "data", time.Millisecond)

	// Wait for expiry.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get("ephemeral")
	if ok {
		t.Error("expected expired entry to be evicted on Get")
	}

	// Entry should be removed from the cache.
	if c.Len() != 0 {
		t.Errorf("Len() = %d after expired Get, want 0", c.Len())
	}
}

func TestSetWithTTL_ZeroTTL(t *testing.T) {
	c := New(Options{MaxEntries: 100})

	// Zero TTL means never expires.
	c.SetWithTTL("forever", "data", 0)

	val, ok := c.Get("forever")
	if !ok {
		t.Fatal("expected 'forever' to exist")
	}
	if val != "data" {
		t.Errorf("Get(forever) = %v, want 'data'", val)
	}
}

func TestSet_OverwriteExisting(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	c.Set("key", "v1")
	c.Set("key", "v2")

	val, ok := c.Get("key")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if val != "v2" {
		t.Errorf("Get(key) = %v, want 'v2' (overwritten)", val)
	}

	if c.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (overwrite, not duplicate)", c.Len())
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(Options{MaxEntries: 3, DefaultTTL: time.Minute})

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	// Cache is full. Adding "d" should evict "a" (least recently used).
	c.Set("d", 4)

	if c.Len() != 3 {
		t.Errorf("Len() = %d, want 3 (after eviction)", c.Len())
	}

	_, ok := c.Get("a")
	if ok {
		t.Error("expected 'a' to be evicted (LRU)")
	}

	val, ok := c.Get("d")
	if !ok {
		t.Fatal("expected 'd' to exist")
	}
	if val != 4 {
		t.Errorf("Get(d) = %v, want 4", val)
	}
}

func TestLRUEviction_AccessUpdatesOrder(t *testing.T) {
	c := New(Options{MaxEntries: 3, DefaultTTL: time.Minute})

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	// Access "a" to make it recently used.
	c.Get("a")

	// Adding "d" should now evict "b" (least recently used).
	c.Set("d", 4)

	_, ok := c.Get("a")
	if !ok {
		t.Error("expected 'a' to survive (was recently accessed)")
	}

	_, ok = c.Get("b")
	if ok {
		t.Error("expected 'b' to be evicted (LRU after 'a' was accessed)")
	}
}

func TestDelete(t *testing.T) {
	c := New(Options{MaxEntries: 100})

	c.Set("key", "value")
	removed := c.Delete("key")
	if !removed {
		t.Error("Delete should return true for existing key")
	}

	_, ok := c.Get("key")
	if ok {
		t.Error("expected key to be gone after Delete")
	}

	if c.Len() != 0 {
		t.Errorf("Len() = %d after Delete, want 0", c.Len())
	}
}

func TestDelete_Nonexistent(t *testing.T) {
	c := New(Options{MaxEntries: 100})

	removed := c.Delete("nonexistent")
	if removed {
		t.Error("Delete should return false for nonexistent key")
	}
}

func TestInvalidate(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	c.Set("entity:123:context", "data1")
	c.Set("entity:123:embedding", "data2")
	c.Set("entity:456:context", "data3")
	c.Set("prompt:abc", "data4")

	// Invalidate all entries for entity 123.
	removed := c.Invalidate("entity:123")
	if removed != 2 {
		t.Errorf("Invalidate removed %d entries, want 2", removed)
	}

	if c.Len() != 2 {
		t.Errorf("Len() = %d after Invalidate, want 2", c.Len())
	}

	// entity:456 and prompt:abc should survive.
	if _, ok := c.Get("entity:456:context"); !ok {
		t.Error("expected entity:456 to survive invalidation")
	}
	if _, ok := c.Get("prompt:abc"); !ok {
		t.Error("expected prompt:abc to survive invalidation")
	}
}

func TestClear(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	c.Clear()

	if c.Len() != 0 {
		t.Errorf("Len() = %d after Clear, want 0", c.Len())
	}
}

func TestStats(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	c.Set("key", "value")

	// 2 hits.
	c.Get("key")
	c.Get("key")

	// 1 miss.
	c.Get("nonexistent")

	hits, misses := c.Stats()
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if misses != 1 {
		t.Errorf("misses = %d, want 1", misses)
	}
}

func TestConcurrentAccess(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Minute})

	// Run concurrent reads and writes to verify thread safety.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			key := fmt.Sprintf("key-%d", id)
			c.Set(key, id)
			c.Get(key)
			c.Delete(key)
		}(i)
	}

	// Wait for all goroutines.
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDefaultTTL(t *testing.T) {
	c := New(Options{MaxEntries: 100, DefaultTTL: time.Millisecond})

	c.Set("key", "value")

	// Wait for default TTL to expire.
	time.Sleep(5 * time.Millisecond)

	_, ok := c.Get("key")
	if ok {
		t.Error("expected entry to expire via default TTL")
	}
}
