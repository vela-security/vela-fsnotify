package fsnotify

import (
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/lua"
	"reflect"
)

var (
	xEnv   assert.Environment
	typeof = reflect.TypeOf((*watch)(nil)).String()
)

/*

 */

func newLuaFsnotify(L *lua.LState) int {
	cfg := newConfig(L)
	proc := L.NewProc(cfg.name, typeof)
	if proc.IsNil() {
		proc.Set(newWatch(cfg))
	} else {
		w := proc.Data.(*watch)
		xEnv.Free(w.cfg.co)
		w.cfg = cfg
	}

	L.Push(proc)
	return 1
}

func WithEnv(env assert.Environment) {
	xEnv = env
	env.Set("fsnotify", lua.NewFunction(newLuaFsnotify))
}
