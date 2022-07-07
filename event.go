package fsnotify

import (
	"github.com/fsnotify/fsnotify"
	"github.com/vela-security/vela-public/lua"
	vtime "github.com/vela-security/vela-time"
	"time"
)

type event struct {
	time   time.Time
	fevent fsnotify.Event
}

func (ev event) Type() lua.LValueType                   { return lua.LTObject }
func (ev event) AssertFloat64() (float64, bool)         { return 0, false }
func (ev event) AssertString() (string, bool)           { return "", false }
func (ev event) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (ev event) Peek() lua.LValue                       { return ev }

func (ev event) String() string {
	return ev.time.Format("2006-01-02.15:04:05") + " " + ev.fevent.String()
}

func (ev event) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "op":
		return lua.S2L(ev.fevent.Op.String())
	case "name":
		return lua.S2L(ev.fevent.Name)
	case "time":
		return vtime.VTime(ev.time)
	case "create":
		return lua.LBool(ev.fevent.Op&fsnotify.Create == fsnotify.Create)

	case "write":
		return lua.LBool(ev.fevent.Op&fsnotify.Write == fsnotify.Write)

	case "remove":
		return lua.LBool(ev.fevent.Op&fsnotify.Remove == fsnotify.Remove)

	case "rename":
		return lua.LBool(ev.fevent.Op&fsnotify.Rename == fsnotify.Rename)

	case "chmod":
		return lua.LBool(ev.fevent.Op&fsnotify.Chmod == fsnotify.Chmod)

	}
	return lua.LNil
}

func (ev *event) dup(old event) bool {
	if ev.fevent.Op != old.fevent.Op {
		return false
	}
	if ev.fevent.Name != old.fevent.Name {
		return false
	}

	if ev.time.UnixMilli()-old.time.UnixMilli() > 50 {
		return false
	}

	return true

}
