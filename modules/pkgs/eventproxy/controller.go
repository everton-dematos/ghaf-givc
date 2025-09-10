// Copyright 2025 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0
package eventproxy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	givc_event "givc/modules/api/event"
	givc_types "givc/modules/pkgs/types"

	"github.com/fsnotify/fsnotify"
	evdev "github.com/holoplot/go-evdev"
	"github.com/jbdemonte/virtual-device/gamepad"

	log "github.com/sirupsen/logrus"
)

type EventProxyController struct {
	transportConfig givc_types.TransportConfig
	virtualGamepad  gamepad.VirtualGamepad
}

// NewEventProxyController creates a new EventProxyController instance.
// It sets up a tcp connection for communication.
func NewEventProxyController(transportConfig givc_types.TransportConfig) (*EventProxyController, error) {
	return &EventProxyController{transportConfig: transportConfig}, nil
}

func (s *EventProxyController) WaitForConsumer() (net.Conn, error) {
	deadline := time.Now().Add(60 * time.Second)
	var conn net.Conn
	var err error
	addr := s.transportConfig.Address + ":" + s.transportConfig.Port

	for time.Now().Before(deadline) {
		conn, err = net.Dial(s.transportConfig.Protocol, addr)
		if err == nil {
			log.Infof("event: successfully connected to consumer.")
			return conn, nil
		}
		log.Infof("event: consumer not ready, retrying in 1 second...")
		time.Sleep(1 * time.Second)
	}
	return nil, err
}

func (s *EventProxyController) ExtractDeviceInfo(dev *evdev.InputDevice) (*givc_event.DeviceInfo, error) {

	inputID, err := dev.InputID()
	if err != nil {
		return nil, err
	}

	name, err := dev.Name()
	if err != nil {
		return nil, err
	}

	deviceInfo := &givc_event.DeviceInfo{
		VendorId: uint32(inputID.Vendor),
		DeviceId: uint32(inputID.Product),
		Name:     name,
	}
	return deviceInfo, nil
}

func checkDevice(deviceName string, event string) bool {

	devicePaths, err := evdev.ListDevicePaths()
	if err == nil {
		for _, dev := range devicePaths {
			if strings.Contains(strings.ToLower(dev.Name), strings.ToLower(deviceName)) && dev.Path == event {
				log.Infof("event: device attached: %s", dev.Name)
				return true
			}
		}
	}
	return false
}

func (s *EventProxyController) MonitorInputDevices(targetDevice string, onAdd func(string)) (string, error) {
	log.Infof("event: Monitoring started for device: %s", targetDevice)
	// Create a channel to signal when the target device is found
	done := make(chan struct{})

	var handler string
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return "", fmt.Errorf("event: failed to create watcher %w", err)
	}
	defer watcher.Close()

	inputDir := "/dev/input"
	if err := watcher.Add(inputDir); err != nil {
		return "", fmt.Errorf("event: failed to watch %s: %w", inputDir, err)
	}

	// Check existing devices at start
	filepath.Walk(inputDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && info.Mode()&os.ModeCharDevice != 0 && strings.HasPrefix(filepath.Base(path), "event") {
			if checkDevice(targetDevice, path) {
				handler = path
				close(done) // Signal that the target device is found
				return nil
			}
			onAdd(path)
		}
		return nil
	})

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Create == fsnotify.Create && strings.HasPrefix(filepath.Base(event.Name), "event") {
					if checkDevice(targetDevice, event.Name) {
						handler = event.Name
						close(done) // Signal that the target device is found
						return
					}
					onAdd(event.Name)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Errorf("event: watch error %v", err)
			}
		}
	}()
	<-done // Wait until the target device is found or an error occurs
	return handler, nil
}

// Closes the socket listener.
func (s *EventProxyController) Close() error {
	if s.virtualGamepad != nil {
		err := s.virtualGamepad.Unregister()
		if err != nil {
			return err
		}
	}
	return nil
}
