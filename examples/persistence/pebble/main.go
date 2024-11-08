// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co, werbenhu
// SPDX-FileContributor: werbenhu

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	mqtt "github.com/xyzj/mqtt-server"
	"github.com/xyzj/mqtt-server/hooks/auth"
	"github.com/xyzj/mqtt-server/hooks/storage/pebble"
	"github.com/xyzj/mqtt-server/listeners"
)

func main() {
	pebblePath := ".pebble"
	defer os.RemoveAll(pebblePath) // remove the example pebble files at the end

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	server := mqtt.New(nil)
	_ = server.AddHook(new(auth.AllowHook), nil)

	err := server.AddHook(new(pebble.Hook), &pebble.Options{
		Path: pebblePath,
		Mode: pebble.NoSync,
	})
	if err != nil {
		log.Fatal(err)
	}

	tcp := listeners.NewTCP(listeners.Config{
		ID:      "t1",
		Address: ":1883",
	})
	err = server.AddListener(tcp)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	<-done
	server.Log.Warn("caught signal, stopping...")
	_ = server.Close()
	server.Log.Info("main.go finished")
}
