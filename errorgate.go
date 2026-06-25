package caddy_error_gate

import (
	"bytes"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	texttemplate "text/template"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

//go:embed templates/*
var templatesFS embed.FS

func init() {
	caddy.RegisterModule(ErrorGate{})
	httpcaddyfile.RegisterHandlerDirective("error_gate", parseCaddyfile)

	// 让用户可以不写全局 order，直接在普通 site block 使用。
	// 但我还是建议实际配置里用 route，顺序更像玻璃一样透明。
	httpcaddyfile.RegisterDirectiveOrder("error_gate", httpcaddyfile.Before, "reverse_proxy")
}

type ErrorGate struct {
	TraceHeader  string `json:"trace_header,omitempty"`
	Exclude      []int  `json:"exclude,omitempty"`
	MinStatus    int    `json:"min_status,omitempty"`
	MaxStatus    int    `json:"max_status,omitempty"`
	HTMLTemplate string `json:"html_template,omitempty"`
	JSONTemplate string `json:"json_template,omitempty"`

	excludeSet map[int]struct{}
	tpl        *template.Template
	jsonTpl    *texttemplate.Template
}

func (ErrorGate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.error_gate",
		New: func() caddy.Module { return new(ErrorGate) },
	}
}

func (g *ErrorGate) Provision(caddy.Context) error {
	if g.TraceHeader == "" {
		g.TraceHeader = "X-Trace-Id"
	}
	if g.MinStatus == 0 {
		g.MinStatus = 400
	}
	if g.MaxStatus == 0 {
		g.MaxStatus = 599
	}

	g.excludeSet = make(map[int]struct{}, len(g.Exclude))
	for _, code := range g.Exclude {
		g.excludeSet[code] = struct{}{}
	}

	funcMap := template.FuncMap{
		"jsonEscape": jsonEscape,
	}

	if g.HTMLTemplate != "" {
		tpl := template.New(filepath.Base(g.HTMLTemplate)).Funcs(funcMap)
		tpl, err := tpl.ParseFiles(g.HTMLTemplate)
		if err != nil {
			return fmt.Errorf("parsing custom html template %q: %w", g.HTMLTemplate, err)
		}
		g.tpl = tpl
	} else {
		tpl := template.New("default.html").Funcs(funcMap)
		tpl, err := tpl.ParseFS(templatesFS, "templates/default.html")
		if err != nil {
			return fmt.Errorf("parsing embedded error template: %w", err)
		}
		g.tpl = tpl
	}

	jsonFuncMap := texttemplate.FuncMap{
		"jsonEscape": jsonEscape,
	}

	if g.JSONTemplate != "" {
		jsonTpl := texttemplate.New(filepath.Base(g.JSONTemplate)).Funcs(jsonFuncMap)
		jsonTpl, err := jsonTpl.ParseFiles(g.JSONTemplate)
		if err != nil {
			return fmt.Errorf("parsing custom json template %q: %w", g.JSONTemplate, err)
		}
		g.jsonTpl = jsonTpl
	} else {
		jsonTpl := texttemplate.New("default.json").Funcs(jsonFuncMap)
		jsonTpl, err := jsonTpl.ParseFS(templatesFS, "templates/default.json")
		if err != nil {
			return fmt.Errorf("parsing embedded json template: %w", err)
		}
		g.jsonTpl = jsonTpl
	}

	return nil
}

func (g ErrorGate) Validate() error {
	if g.MinStatus < 100 || g.MaxStatus > 599 || g.MinStatus > g.MaxStatus {
		return fmt.Errorf("invalid status range: %d-%d", g.MinStatus, g.MaxStatus)
	}
	for _, code := range g.Exclude {
		if code < 100 || code > 599 {
			return fmt.Errorf("invalid excluded status code: %d", code)
		}
	}
	return nil
}

func (g ErrorGate) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	traceID := r.Header.Get(g.TraceHeader)
	if traceID == "" {
		traceID = newTraceID()
		r.Header.Set(g.TraceHeader, traceID)
	}
	w.Header().Set(g.TraceHeader, traceID)

	// 不要碰升级连接，WebSocket 这些让 reverse_proxy 自己飞。
	if isUpgradeRequest(r) {
		return next.ServeHTTP(w, r)
	}

	rec := newCaptureResponseWriter(w)

	err := next.ServeHTTP(rec, r)
	if err != nil {
		return g.render(w, r, http.StatusBadGateway, traceID, rec.header, nil)
	}

	if !g.shouldIntercept(rec.status) {
		return rec.flushOriginal()
	}

	return g.render(w, r, rec.status, traceID, rec.header, rec.body.Bytes())
}

func (g ErrorGate) shouldIntercept(status int) bool {
	if status < g.MinStatus || status > g.MaxStatus {
		return false
	}
	_, excluded := g.excludeSet[status]
	return !excluded
}

func (g ErrorGate) render(w http.ResponseWriter, r *http.Request, status int, traceID string, originalHeader http.Header, bodyBytes []byte) error {
	var buf bytes.Buffer
	var contentType string
	var err error

	msg := extractUpstreamMessage(bodyBytes)
	if msg == "" {
		msg = http.StatusText(status)
	}

	lang := getLanguage(r)
	i18nData := getI18n(lang, status)

	data := map[string]any{
		"Status":      status,
		"Text":        http.StatusText(status),
		"TraceID":     traceID,
		"Message":     msg,
		"Description": i18nData.Description,
		"I18n":        i18nData,
	}

	if wantsJSON(r) {
		contentType = "application/json; charset=utf-8"
		err = g.jsonTpl.Execute(&buf, data)
	} else {
		contentType = "text/html; charset=utf-8"
		err = g.tpl.Execute(&buf, data)
	}

	if err != nil {
		buf.Reset()
		buf.WriteString(fmt.Sprintf("%d %s (Trace ID: %s)", status, http.StatusText(status), traceID))
		contentType = "text/plain; charset=utf-8"
	}

	// Copy headers from original response
	dstHeader := w.Header()
	for k, values := range originalHeader {
		dstHeader[k] = values
	}

	// Strip cache headers
	dstHeader.Del("Age")
	dstHeader.Del("CDN-Cache-Control")
	dstHeader.Del("Cloudflare-CDN-Cache-Control")
	dstHeader.Del("Surrogate-Control")
	dstHeader.Del("ETag")
	dstHeader.Del("Last-Modified")

	// Set standard cache control headers to prevent caching
	dstHeader.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	dstHeader.Set("Pragma", "no-cache")
	dstHeader.Set("Expires", "0")

	// Strip content headers that are no longer valid for the new body
	dstHeader.Del("Content-Length")
	dstHeader.Del("Content-Encoding")
	dstHeader.Del("Content-Range")
	dstHeader.Del("Accept-Ranges")

	// Set/overwrite custom headers
	dstHeader.Set("Content-Type", contentType)
	dstHeader.Set(g.TraceHeader, traceID)

	w.WriteHeader(status)
	_, writeErr := w.Write(buf.Bytes())
	return writeErr
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
//
// Syntax:
//
//	error_gate {
//	    trace_header <header>
//	    exclude <status...>
//	    status_range <min> <max>
//	}
func (g *ErrorGate) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "trace_header":
				if !d.NextArg() {
					return d.ArgErr()
				}
				g.TraceHeader = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			case "exclude":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				for _, arg := range args {
					code, err := strconv.Atoi(arg)
					if err != nil {
						return d.Errf("invalid status code %q", arg)
					}
					g.Exclude = append(g.Exclude, code)
				}

			case "status_range":
				var minStr, maxStr string
				if !d.Args(&minStr, &maxStr) {
					return d.ArgErr()
				}
				minStatus, err := strconv.Atoi(minStr)
				if err != nil {
					return d.Errf("invalid min status %q", minStr)
				}
				maxStatus, err := strconv.Atoi(maxStr)
				if err != nil {
					return d.Errf("invalid max status %q", maxStr)
				}
				g.MinStatus = minStatus
				g.MaxStatus = maxStatus

			case "html_template":
				if !d.NextArg() {
					return d.ArgErr()
				}
				g.HTMLTemplate = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			case "json_template":
				if !d.NextArg() {
					return d.ArgErr()
				}
				g.JSONTemplate = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}

			default:
				return d.Errf("unknown error_gate option: %s", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var g ErrorGate
	err := g.UnmarshalCaddyfile(h.Dispenser)
	return &g, err
}

func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "trace-unknown"
	}
	return hex.EncodeToString(b[:])
}

func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}

	return false
}

func isUpgradeRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "upgrade") ||
		r.Header.Get("Upgrade") != ""
}

func extractUpstreamMessage(bodyBytes []byte) string {
	if len(bodyBytes) == 0 {
		return ""
	}

	var upstreamJSON map[string]any
	if err := json.Unmarshal(bodyBytes, &upstreamJSON); err != nil {
		return ""
	}

	for _, key := range []string{"message", "msg", "detail"} {
		if val, ok := upstreamJSON[key]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal
			}
			if val != nil {
				return fmt.Sprintf("%v", val)
			}
		}
	}
	return ""
}

func jsonEscape(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func getStatusDescription(status int) string {
	switch status {
	case 400:
		return "呜呜，请求好像有点小脾气，服务器看不懂啦。请检查一下参数、格式或者 URL 再试一次嘛~(>_<)"
	case 401:
		return "站住！这里是神秘区域哦，需要输入正确的身份凭证（钥匙）才能通过呢~ 🔑"
	case 403:
		return "唔…虽然你亮明了身份，但本大人还是不能让你过去。这里是禁止通行的禁区哦！"
	case 404:
		return "诶？你找的页面好像和本喵走丢了，在宇宙深处迷路了喵~ 🐾"
	case 405:
		return "这个请求姿势（Method）不对啦！服务器说它不能接受这种敲门方式哦~"
	case 407:
		return "代理服务器拦住你啦！需要先通过代理身份验证哦~"
	case 408:
		return "等得花儿都谢了……请求超时啦，网速可能在开小差，重新发送一下试试？"
	case 409:
		return "哎呀，服务器内部发生了点小摩擦（冲突），大家在抢同一个资源呢，稍等下再来试试呗？"
	case 410:
		return "那个宝贵的资源已经彻底搬家啦，而且没有留下新地址，追不回来啦QAQ"
	case 411:
		return "服务器需要知道你发的数据有多长，请在请求里加上长度信息（Content-Length）哦~"
	case 413:
		return "哇！你给的数据包太胖啦，服务器抱不动了！快去给它瘦个身吧~"
	case 418:
		return "人家其实是一只茶壶啦，泡茶我在行，处理请求真的超纲了咩~ 🍵"
	case 429:
		return "手速太快啦！服务器要被你戳晕了，先喝杯茶休息一下再来敲门吧~ ☕"
	case 500:
		return "抱歉哦，服务器的小马达突然卡住了，程序员哥哥正在疯狂抢修中！"
	case 501:
		return "这个功能服务器还没学会呢，等程序员哥哥把它开发出来吧~"
	case 502:
		return "哎呀，网关在帮别的服务器传话时，对方突然断线了，真是个糟糕的传话筒！"
	case 503:
		return "服务器今天太累了，正在闭关修炼（维护中）或者被大家挤爆了，稍后再来找我玩吧~"
	case 504:
		return "呜，上游服务器迟迟没有回音，网关等到花儿都谢了也只能放弃啦。"
	default:
		if status >= 400 && status < 500 {
			return "客户端好像出了点状况，请求没办法顺利完成，检查下小细节吧~"
		}
		if status >= 500 && status < 600 {
			return "服务器内部好像有点头晕，暂时没办法处理你的请求，请稍候再试喵~"
		}
		return "遭遇了未知的神秘状况呢，请稍后再试一次吧~"
	}
}

var (
	_ caddy.Module                = (*ErrorGate)(nil)
	_ caddy.Provisioner           = (*ErrorGate)(nil)
	_ caddy.Validator             = (*ErrorGate)(nil)
	_ caddyfile.Unmarshaler       = (*ErrorGate)(nil)
	_ caddyhttp.MiddlewareHandler = (*ErrorGate)(nil)
)
