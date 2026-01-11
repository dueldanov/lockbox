package restapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/pkg/errors"
	"go.uber.org/dig"
	"golang.org/x/time/rate"

	"github.com/iotaledger/hive.go/app"
	"github.com/iotaledger/hive.go/runtime/event"
	"github.com/dueldanov/lockbox/v2/pkg/components"
	"github.com/dueldanov/lockbox/v2/pkg/daemon"
	"github.com/dueldanov/lockbox/v2/pkg/jwt"
	"github.com/dueldanov/lockbox/v2/pkg/metrics"
	"github.com/dueldanov/lockbox/v2/pkg/tangle"
	"github.com/iotaledger/inx-app/pkg/httpserver"
)

func init() {
	Component = &app.Component{
		Name:             "RestAPI",
		DepsFunc:         func(cDeps dependencies) { deps = cDeps },
		Params:           params,
		InitConfigParams: initConfigParams,
		IsEnabled: func(c *dig.Container) bool {
			// do not enable in "autopeering entry node" mode
			return components.IsAutopeeringEntryNodeDisabled(c) && ParamsRestAPI.Enabled
		},
		Provide:   provide,
		Configure: configure,
		Run:       run,
	}
}

var (
	Component *app.Component
	deps      dependencies
	jwtAuth   *jwt.Auth
)

// SECURITY: IP-based rate limiter to prevent DoS attacks
type ipRateLimiter struct {
	limiters sync.Map
	rate     rate.Limit
	burst    int
}

func newIPRateLimiter(r float64, b int) *ipRateLimiter {
	return &ipRateLimiter{
		rate:  rate.Limit(r),
		burst: b,
	}
}

func (i *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	if limiter, ok := i.limiters.Load(ip); ok {
		return limiter.(*rate.Limiter)
	}
	limiter := rate.NewLimiter(i.rate, i.burst)
	i.limiters.Store(ip, limiter)
	return limiter
}

func rateLimitMiddleware(rl *ipRateLimiter) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			limiter := rl.getLimiter(ip)
			if !limiter.Allow() {
				return echo.NewHTTPError(http.StatusTooManyRequests, "rate limit exceeded")
			}
			return next(c)
		}
	}
}

type dependencies struct {
	dig.In
	Tangle             *tangle.Tangle `optional:"true"`
	Echo               *echo.Echo
	RestAPIMetrics     *metrics.RestAPIMetrics
	Host               host.Host
	RestAPIBindAddress string         `name:"restAPIBindAddress"`
	NodePrivateKey     crypto.PrivKey `name:"nodePrivateKey"`
	RestRouteManager   *RestRouteManager
}

func initConfigParams(c *dig.Container) error {

	type cfgResult struct {
		dig.Out
		RestAPIBindAddress      string `name:"restAPIBindAddress"`
		RestAPILimitsMaxResults int    `name:"restAPILimitsMaxResults"`
	}

	if err := c.Provide(func() cfgResult {
		return cfgResult{
			RestAPIBindAddress:      ParamsRestAPI.BindAddress,
			RestAPILimitsMaxResults: ParamsRestAPI.Limits.MaxResults,
		}
	}); err != nil {
		Component.LogPanic(err)
	}

	return nil
}

func provide(c *dig.Container) error {

	if err := c.Provide(func() *metrics.RestAPIMetrics {
		return &metrics.RestAPIMetrics{
			Events: &metrics.RestAPIEvents{
				PoWCompleted: event.New2[int, time.Duration](),
			},
		}
	}); err != nil {
		Component.LogPanic(err)
	}

	if err := c.Provide(func() *echo.Echo {

		e := httpserver.NewEcho(
			Component.Logger(),
			func(err error, c echo.Context) {
				deps.RestAPIMetrics.HTTPRequestErrorCounter.Inc()
			},
			ParamsRestAPI.DebugRequestLoggerEnabled,
		)
		e.Use(middleware.CORS())
		if ParamsRestAPI.UseGZIP {
			e.Use(middleware.Gzip())
		}
		e.Use(middleware.BodyLimit(ParamsRestAPI.Limits.MaxBodyLength))

		return e
	}); err != nil {
		Component.LogPanic(err)
	}

	type proxyDeps struct {
		dig.In
		Echo *echo.Echo
	}

	if err := c.Provide(func(deps proxyDeps) *RestRouteManager {
		return newRestRouteManager(deps.Echo)
	}); err != nil {
		Component.LogPanic(err)
	}

	return nil
}

func configure() error {
	// SECURITY: Add rate limiting middleware if enabled
	if ParamsRestAPI.RateLimiting.Enabled {
		rl := newIPRateLimiter(
			ParamsRestAPI.RateLimiting.MaxRequestsPerSecond,
			ParamsRestAPI.RateLimiting.Burst,
		)
		deps.Echo.Use(rateLimitMiddleware(rl))
		Component.LogInfof("Rate limiting enabled: %.1f req/s, burst %d",
			ParamsRestAPI.RateLimiting.MaxRequestsPerSecond,
			ParamsRestAPI.RateLimiting.Burst)
	}

	deps.Echo.Use(apiMiddleware())
	setupRoutes()

	return nil
}

func run() error {

	Component.LogInfo("Starting REST-API server ...")

	if err := Component.Daemon().BackgroundWorker("REST-API server", func(ctx context.Context) {
		Component.LogInfo("Starting REST-API server ... done")

		bindAddr := deps.RestAPIBindAddress

		go func() {
			Component.LogInfof("You can now access the API using: http://%s", bindAddr)
			if err := deps.Echo.Start(bindAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				Component.LogWarnf("Stopped REST-API server due to an error (%s)", err)
			}
		}()

		<-ctx.Done()
		Component.LogInfo("Stopping REST-API server ...")

		shutdownCtx, shutdownCtxCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCtxCancel()

		//nolint:contextcheck // false positive
		if err := deps.Echo.Shutdown(shutdownCtx); err != nil {
			Component.LogWarn(err)
		}

		Component.LogInfo("Stopping REST-API server ... done")
	}, daemon.PriorityRestAPI); err != nil {
		Component.LogPanicf("failed to start worker: %s", err)
	}

	return nil
}
