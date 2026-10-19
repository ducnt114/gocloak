package service

import "context"

// Cache invalidation topics sent between cluster nodes.
const topicKeys = "keys"

// RunInvalidation applies the cache invalidations sent by the other nodes
// of a cluster (PostgreSQL) until ctx ends.
func (s *Service) RunInvalidation(ctx context.Context) {
	s.Store.OnListenError = func(err error) { s.logger().Warn("cluster invalidation listener", "err", err) }
	s.Store.Listen(ctx, func(topic, key string) {
		switch topic {
		case topicKeys:
			s.invalidateKeysLocal(key)
		}
	}, func() {
		// notifications may have been missed while disconnected
		s.invalidateKeysLocal("")
	})
}
