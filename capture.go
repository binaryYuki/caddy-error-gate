package caddy_error_gate

import (
	"bytes"
	"net/http"
)

type captureResponseWriter struct {
	original    http.ResponseWriter
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func newCaptureResponseWriter(w http.ResponseWriter) *captureResponseWriter {
	return &captureResponseWriter{
		original: w,
		header:   make(http.Header),
		status:   http.StatusOK,
	}
}

func (w *captureResponseWriter) Header() http.Header {
	return w.header
}

func (w *captureResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

func (w *captureResponseWriter) flushOriginal() error {
	dst := w.original.Header()

	for k, values := range w.header {
		dst.Del(k)
		for _, v := range values {
			dst.Add(k, v)
		}
	}

	w.original.WriteHeader(w.status)

	if w.body.Len() > 0 {
		_, err := w.original.Write(w.body.Bytes())
		return err
	}

	return nil
}
