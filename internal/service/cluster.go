package service

import (
	"context"

	"github.com/ducnt114/gocloak/internal/store"
)

// Cache invalidation topics sent between cluster nodes.
const topicKeys = "keys"

// RunInvalidation applies the cache invalidations sent by the other nodes
// of a cluster (PostgreSQL) until ctx ends.
func (s *Service) RunInvalidation(ctx context.Context) {
	s.Store.OnListenError = func(err error) { s.logger().Warn("cluster invalidation listener", "err", err) }
	s.Store.Listen(ctx, func(topic, key string) {
		// keys are loaded from cached components, and the two
		// notifications of a key change may come in either order
		switch topic {
		case topicKeys:
			s.Store.InvalidateConfigCache()
			s.invalidateKeysLocal(key)
		case store.TopicConfig:
			s.Store.InvalidateConfigCache()
			s.invalidateKeysLocal("")
		}
	}, func() {
		// notifications may have been missed while disconnected
		s.Store.InvalidateConfigCache()
		s.invalidateKeysLocal("")
	})
}
