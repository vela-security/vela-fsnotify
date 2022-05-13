package fsnotify

import (
	"context"
	"github.com/fsnotify/fsnotify"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
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

func (w *watch) pipeEv(ev fsnotify.Event) {
	w.cfg.pipe.Do(event(ev), w.cfg.co, func(err error) {
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
		for {
			select {
			case <-w.ctx.Done():
				xEnv.Errorf("%s exit", w.Name())
				return
			case ev, ok := <-w.fw.Events:
				if !ok {
					return
				}
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

func (w *watch) lAdd(L *lua.LState) int {
	n := L.GetTop()
	if n == 0 {
		return 0
	}
	ctc := catch.New()
	for i := 1; i <= n; i++ {
		if filename := L.IsString(i); filename != "" {
			w.append(filename)
			ctc.Try(filename, w.fw.Add(filename))
		}
	}

	if e := ctc.Wrap(); e == nil {
		return 0
	} else {
		L.Push(lua.S2L(e.Error()))
		return 1
	}
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

func (w *watch) pipeL(L *lua.LState) int {
	w.cfg.pipe.CheckMany(L, pipe.Seek(0))
	return 0
}

func (w *watch) onErrL(L *lua.LState) int {
	w.cfg.pipe.CheckMany(L, pipe.Seek(0))
	return 0
}

func (w *watch) startL(L *lua.LState) int {
	xEnv.Start(L, w).From(w.CodeVM()).Do()
	return 0
}

func (w *watch) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "start":
		return lua.NewFunction(w.startL)
	case "pipe":
		return lua.NewFunction(w.pipeL)
	case "on_err":
		return lua.NewFunction(w.onErrL)
	case "add":
		return L.NewFunction(w.lAdd)
	case "clean":
		return L.NewFunction(w.clean)
	}

	return lua.LNil
}
