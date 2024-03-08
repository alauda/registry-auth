package server

import (
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"

	"gopkg.in/fsnotify.v1"
)

func readConfigFile(path string, p *AuthProcessor) error {
	logger.Info(fmt.Sprintf("read config file from %s", path), zap.String("func", "readConfigFile"))
	data, err := ioutil.ReadFile(path)
	if err != nil {
		logger.Error(fmt.Sprintf(`read config file from "%s" error: %v`, path, err), zap.String("func", "readConfigFile"))
		return err
	}
	if err := p.LoadFromFile(data); err != nil {
		logger.Error(fmt.Sprintf(`load config file from "%s" error: %v`, path, err), zap.String("func", "readConfigFile"))
	}
	return err
}

func WatchConfigFile(path string, stop <-chan struct{}, p *AuthProcessor) error {
	logger.Info(fmt.Sprintf("staring watch config file %s", path), zap.String("func", "WatchConfigFile"))
	if err := readConfigFile(path, p); err != nil {
		return err
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := w.Add(path); err != nil {
		return err
	}

	go func() {
		stopped := false
		for !stopped {
			select {
			case <-stop:
				stopped = true
			case ev := <-w.Events:
				if ev.Op == fsnotify.Create || ev.Op == fsnotify.Write {
					readConfigFile(path, p)
				}
			}
		}
	}()
	logger.Info(fmt.Sprintf("watch config file %s successfully", path), zap.String("func", "WatchConfigFile"))
	return nil
}
