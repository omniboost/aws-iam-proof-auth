package ttlcache

import "time"

// SetClock overrides the cache's time source. It is only available to tests.
func (c *TTL[V]) SetClock(now func() time.Time) {
	c.setClock(now)
}
