package ipwhoisserver // import "cirello.io/ipwhois/ipwhoisserver"

import (
	"context"
	"strings"
	"sync"
	"time"

	ipwhois "cirello.io/ipwhois"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

// Response to a Query asking what country is owner of a given IP.
type Response struct {
	Country string
	Err     error
	Cached  bool
}

// Query holds what's the target that the ipwhoisserver should investigate for
// country ownership.
type Query struct {
	IP       string
	Response chan *Response
}

// NewQuery creates the query that the server can use to execute queries and
// not leak goroutines.
func NewQuery(ip string) *Query {
	response := make(chan *Response, 1)
	return &Query{
		IP:       ip,
		Response: response,
	}
}

type cachedIP struct {
	country string
	when    time.Time
}

// Serve execute Queries and provide their answer as channel-in-channel.
// Cancel the given context to stop the clockwork. Use NewQuery to create
// the requests in a way to avoid goroutine leaks. The internal cache table
// evicts entries older than 12h.
func Serve(ctx context.Context, reqs <-chan *Query) {
	limiter := rate.NewLimiter(rate.Every(1*time.Minute), 30)
	var (
		mu         sync.RWMutex
		cacheTable = make(map[string]cachedIP)
	)
	var singleflightGroup singleflight.Group
	for req := range reqs {
		if ctx.Err() != nil {
			return
		}
		req := req
		go func() {
			normalizedQuery := strings.TrimSpace(req.IP)
			mu.RLock()
			cached, ok := cacheTable[normalizedQuery]
			mu.RUnlock()
			if ok && time.Since(cached.when) <= 12*time.Hour {
				req.Response <- &Response{cached.country, nil, true}
				return
			}
			resp, err, shared := singleflightGroup.Do(normalizedQuery, func() (interface{}, error) {
				limiter.Wait(ctx)
				country, err := ipwhois.Query(ctx, normalizedQuery)
				if err != nil {
					return country, err
				}
				mu.Lock()
				cacheTable[normalizedQuery] = cachedIP{
					country: country,
					when:    time.Now(),
				}
				mu.Unlock()
				return country, nil
			})
			select {
			case req.Response <- &Response{resp.(string), err, shared}:
				close(req.Response)
			default:
			}
		}()
	}
}
