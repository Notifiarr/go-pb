package main

import (
	"context"
	"log"

	"github.com/iliafrenkel/go-pb/src/api/db/memory"
	"github.com/iliafrenkel/go-pb/src/api/http"
)

var apiServer *http.ApiServer

func StartApiServer(opts http.ApiServerOptions) error {
	apiServer = http.New(memory.New(), opts)

	log.Println("API server listening on ", opts.Addr)

	return apiServer.ListenAndServe()
}

func StopApiServer(ctx context.Context) error {
	if apiServer != nil {
		return apiServer.Server.Shutdown(ctx)
	}

	return nil
}