// Minimal RESP stub server: enough of Redis (PING/GET/SET/DEL/EXPIRE/TTL/EXISTS/SETEX/KEYS)
// for the aegis server to boot and pass health checks in the sandbox e2e.
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu    sync.Mutex
	store = map[string]string{}
	expir = map[string]time.Time{}
)

func alive(k string) bool {
	t, ok := expir[k]
	if ok && time.Now().After(t) {
		delete(store, k)
		delete(expir, k)
		return false
	}
	_, ok = store[k]
	return ok
}

func handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		var args []string
		if strings.HasPrefix(line, "*") {
			n, _ := strconv.Atoi(line[1:])
			for i := 0; i < n; i++ {
				hl, _ := r.ReadString('\n')
				hl = strings.TrimSpace(hl)
				ln, _ := strconv.Atoi(strings.TrimPrefix(hl, "$"))
				buf := make([]byte, ln+2)
				r.Read(buf)
				args = append(args, string(buf[:ln]))
			}
		} else if line != "" {
			args = strings.Fields(line)
		}
		if len(args) == 0 {
			continue
		}
		cmd := strings.ToUpper(args[0])
		mu.Lock()
		out := apply(cmd, args[1:])
		mu.Unlock()
		c.Write(out)
	}
}

func apply(cmd string, a []string) []byte {
	switch cmd {
	case "PING":
		return []byte("+PONG\r\n")
	case "HELLO":
		// go-redis falls back to RESP2 when HELLO errors.
		return []byte("-ERR unknown command 'HELLO'\r\n")
	case "AUTH", "SELECT", "CLIENT", "READONLY", "UNWATCH", "WATCH":
		return []byte("+OK\r\n")
	case "INFO":
		return []byte("$0\r\n\r\n")
	case "CONFIG", "COMMAND":
		return []byte("*0\r\n")
	case "GET":
		if len(a) < 1 || !alive(a[0]) {
			return []byte("$-1\r\n")
		}
		v := store[a[0]]
		return []byte(fmt.Sprintf("$%d\r\n%s\r\n", len(v), v))
	case "SET", "SETEX":
		if len(a) < 2 {
			return []byte("+OK\r\n")
		}
		ttl := 0
		if cmd == "SETEX" && len(a) >= 3 {
			ttl, _ = strconv.Atoi(a[1])
			a = append([]string{a[0]}, a[2:]...)
		}
		store[a[0]] = a[1]
		delete(expir, a[0])
		if ttl > 0 {
			expir[a[0]] = time.Now().Add(time.Duration(ttl) * time.Second)
		}
		return []byte("+OK\r\n")
	case "DEL", "EXISTS":
		n := 0
		for _, k := range a {
			if alive(k) {
				n++
				if cmd == "DEL" {
					delete(store, k)
					delete(expir, k)
				}
			}
		}
		return []byte(fmt.Sprintf(":%d\r\n", n))
	case "EXPIRE":
		if len(a) >= 2 && alive(a[0]) {
			sec, _ := strconv.Atoi(a[1])
			expir[a[0]] = time.Now().Add(time.Duration(sec) * time.Second)
			return []byte(":1\r\n")
		}
		return []byte(":0\r\n")
	case "TTL":
		if len(a) >= 1 && alive(a[0]) {
			if t, ok := expir[a[0]]; ok {
				return []byte(fmt.Sprintf(":%d\r\n", int(time.Until(t).Seconds())))
			}
			return []byte(":-1\r\n")
		}
		return []byte(":-2\r\n")
	case "KEYS":
		pat := "*"
		if len(a) >= 1 {
			pat = a[0]
		}
		var ks []string
		for k := range store {
			if alive(k) && match(pat, k) {
				ks = append(ks, k)
			}
		}
		out := fmt.Sprintf("*%d\r\n", len(ks))
		for _, k := range ks {
			out += fmt.Sprintf("$%d\r\n%s\r\n", len(k), k)
		}
		return []byte(out)
	default:
		return []byte("+OK\r\n")
	}
}

func match(pat, s string) bool {
	if pat == "*" {
		return true
	}
	if strings.HasSuffix(pat, "*") {
		return strings.HasPrefix(s, pat[:len(pat)-1])
	}
	return pat == s
}

func main() {
	addr := "127.0.0.1:6379"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("redis-stub listening on", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go handle(c)
	}
}
