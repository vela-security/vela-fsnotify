# fsnotify
文件状态监控

## vela.fsnotify

- userdata = vela.fsnotify{name , path}
- name: 进程名
- path: 监控路径

#### 内部接口
- [userdata.start()]()
- [userdata.filter(cnd)]()
- [userdata.pipe(lua.writer)]()
- [userdata.on_err(lua.writer)]()

#### event
- [event.op string]()
- [event.time time]()
- [event.name string]()
- [event.create bool]()
- [event.write bool]()
- [event.rename bool]()
- [event.chmod bool]()

```lua
    local ud = vela.fsnotify{
        name = "ff",
        path = "/var/log",
    }

    ud.filter("op eq WRITE" , "name re *passwd*") --cond 过滤
    
    ud.pipe(function(ev)
        print(ev.op)
        print(ev.name) -- filename
        print(ev.write) -- true
        print(ev.time) -- true
        
    end)
    
    ud.on_err(function(err)
    end)

    ud.start()
```