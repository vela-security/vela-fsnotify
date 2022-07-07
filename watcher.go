package fsnotify

import (
	"context"
	"github.com/fsnotify/fsnotify"
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/lua"
	"time"
)

type watch struct {
	lua.ProcEx
	cfg    *config
	ctx    context.Context
	cancel context.CancelFunc
	fw     *fsnotify.Watcher
}

func newWatch(cfg *config) *watch {
	return &watch{cfg: cfg}
}

func (w *watch) Name() string {
	return w.cfg.name
}

func (w *watch) filter(ev event) bool {
	if w.cfg.match == nil {
		return true
	}

	return w.cfg.match.Match(ev, cond.WithCo(w.cfg.co))
}

func (w *watch) pipeEv(ev event) {

	w.cfg.pipe.Do(ev, w.cfg.co, func(err error) {
		xEnv.Errorf("%s pipe inotify fail %v", w.Name(), err)
	})
}

func (w *watch) pipeErr(err error) {
	if w.cfg.onErr == nil {
		xEnv.Errorf("%v pipe error %v", w.Name(), err)
		return
	}

	w.cfg.pipe.Do(err, w.cfg.co, func(err error) {
		xEnv.Errorf("%s pipe inotify fail %v", w.Name(), err)
	})
}

func (w *watch) Start() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.fw = watcher
	w.ctx = ctx
	w.cancel = cancel
	xEnv.Spawn(0, func() {
		old := event{}

		for {
			select {
			case <-w.ctx.Done():
				xEnv.Errorf("%s exit", w.Name())
				return
			case fevent, ok := <-w.fw.Events:
				if !ok {
					return
				}

				ev := event{time.Now(), fevent}
				if !w.filter(ev) || ev.dup(old) {
					continue
				}

				old = ev
				w.pipeEv(ev)

			case e, ok := <-w.fw.Errors:
				if !ok {
					return
				}
				w.pipeErr(e)
			}
		}
	})

	if len(w.cfg.path) == 0 {
		return nil
	}

	me := catch.New()
	for _, item := range w.cfg.path {
		me.Try(item, w.fw.Add(item))
	}
	return me.Wrap()
}

func (w *watch) Close() error {
	w.cancel()
	if w.fw != nil {
		return w.fw.Close()
	}
	return nil
}

func (w *watch) Type() string {
	return typeof
}

func (w *watch) append(filename string) {
	n := len(w.cfg.path)
	if n == 0 {
		w.cfg.path = []string{filename}
		return
	}

	for i := 0; i < n; i++ {
		if w.cfg.path[i] == filename {
			return
		}
	}

	w.cfg.path = append(w.cfg.path, filename)
}

func (w *watch) clean(L *lua.LState) int {
	if w.fw == nil {
		return 0
	}

	n := len(w.cfg.path)
	if n == 0 {
		return 0
	}

	for i := 0; i < n; i++ {
		w.fw.Remove(w.cfg.path[i])
	}

	return 0
}
