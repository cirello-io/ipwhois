package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"cirello.io/ipwhois/ipwhoisserver"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	reqs := make(chan *ipwhoisserver.Query)
	go ipwhoisserver.Serve(ctx, reqs)
	scanner := bufio.NewScanner(os.Stdin)
inputLoop:
	for {
		input := make(chan string, 1)
		go func() {
			if !scanner.Scan() {
				cancel()
				return
			}
			input <- scanner.Text()
		}()
		var ip string
		select {
		case <-ctx.Done():
			break inputLoop
		case q := <-input:
			ip = q
		}
		go func() {
			req := ipwhoisserver.NewQuery(ip)
			reqs <- req
			select {
			case <-time.After(1 * time.Second):
				fmt.Println(ip, "timeout")
			case resp := <-req.Response:
				fmt.Println(ip, resp.Country, resp.Err, resp.Cached)
			}
		}()
	}
}
