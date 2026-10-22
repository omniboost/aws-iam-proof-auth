package iamproof

import "time"

// SetClock overrides the memory store's time source. It is only available to
// tests.
func (s *MemoryNonceStore) SetClock(now func() time.Time) {
	s.now = now
}

// Len reports the number of tracked nonces. It is only available to tests.
func (s *MemoryNonceStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
