package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	log.Println("Starting servers...")
	// We start the Web server after the API one so that no web requests
	// come before API is ready. The shutdown is done in reverse order.
	go StartApiServer()
	go StartWebServer()

	// Graceful shutdown - we create a channel for system signals and
	// "subscribe" to SIGINT or SIGTERM. We then wait indefinitely for
	// one of the signals.
	// Once we receive a signal we create a context with timeout to give
	// the servers some time to close all the connections. Please note
	// that the context is shared between the severs. This means that the
	// timeout is for BOTH severs - if the timeout is 10 seconds and web
	// server takes 9 seconds to shutdown it will leave the API server
	// only one second.
	//
	// TODO: Shutdown timeout must be configurable.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down servers:")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := StopWebServer(ctx); err != nil {
		log.Println("\tWeb server forced to shutdown: ", err)
	} else {
		log.Println("\tWeb server is down")
	}

	if err := StopApiServer(ctx); err != nil {
		log.Println("\tAPI server forced to shutdown: ", err)
	} else {
		log.Println("\tAPI server is down")
	}

	log.Println("Servers are down, sayōnara!")
}
