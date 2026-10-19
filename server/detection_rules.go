package main

import (
	"context"
	"time"

	"openxdr/server/internal/sigma"
	"openxdr/server/internal/temporal"
)

func loadDetectionRules(ctx context.Context, baseDir, temporalDir string, interval time.Duration) (sigma.Catalog, *temporal.Store, error) {
	if temporalDir == "" {
		rules := sigma.LoadDir(baseDir)
		if interval > 0 {
			go rules.Watch(ctx, baseDir, interval)
		}
		return rules, nil, nil
	}
	store := &temporal.Store{}
	if err := store.Reload(baseDir, temporalDir); err != nil {
		return nil, nil, err
	}
	if interval > 0 {
		go store.Watch(ctx, baseDir, temporalDir, interval)
	}
	return store, store, nil
}
