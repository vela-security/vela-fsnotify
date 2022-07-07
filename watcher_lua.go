package fsnotify

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

func (w *watch) addL(L *lua.LState) int {
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

func (w *watch) pipeL(L *lua.LState) int {
	w.cfg.pipe.CheckMany(L, pipe.Seek(0))
	return 0
}

func (w *watch) onErrL(L *lua.LState) int {
	w.cfg.onErr.CheckMany(L, pipe.Seek(0))
	return 0
}

func (w *watch) filterL(L *lua.LState) int {
	w.cfg.match = cond.CheckMany(L, cond.WithCo(L))
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
	case "filter":
		return lua.NewFunction(w.filterL)
	case "pipe":
		return lua.NewFunction(w.pipeL)
	case "on_err":
		return lua.NewFunction(w.onErrL)
	case "add":
		return L.NewFunction(w.addL)
	case "clean":
		return L.NewFunction(w.clean)
	}

	return lua.LNil
}
