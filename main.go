package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	flag.Usage = func() {
		fmt.Println("trivy webhook -- -url=<webhook-url> -- <trivy args>")
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(os.Stderr, "     %v\n", f.Usage)
		})
	}
	webhookUrl := flag.String("url", "", "webhook endpoint url")
	flag.Parse()

	if len(*webhookUrl) <= 0 {
		flag.Usage()
		log.Fatal("trivy webhook plugin expects a webhook endpoint url")
	}

	log.Println("running trivy...")
	out, err := runScan(os.Args, exec.Command)
	if err != nil {
		flag.Usage()
		log.Fatal("trivy returned an error: ", err, " output: ", string(out))
	}

	log.Println("sending results to webhook...")
	resp, err := sendToWebhook(*webhookUrl, &http.Client{
		Timeout: time.Second * 30,
	}, out)
	if err != nil {
		log.Fatal("failed to send to webhook: ", err)
	}

	log.Println("webhook returned: ", string(resp))
}

func sendToWebhook(webhookUrl string, nc *http.Client, body []byte) ([]byte, error) {
	resp, err := nc.Post(webhookUrl, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build post request: %w", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return b, nil
}

func runScan(args []string, execCmd func(string, ...string) *exec.Cmd) ([]byte, error) {
	trivyArgsIndex := findTrivySep(args)
	if trivyArgsIndex < 0 {
		return nil, fmt.Errorf("invalid arguments specified")
	}

	trivyArgs := os.Args[trivyArgsIndex:]
	if !containsSlice(trivyArgs, "format") {
		trivyArgs = append(trivyArgs, []string{"--format=json"}...)
	}
	if !containsSlice(trivyArgs, "quiet") {
		trivyArgs = append(trivyArgs, []string{"--quiet"}...)
	}
	if !containsSlice(trivyArgs, "timeout") {
		trivyArgs = append(trivyArgs, []string{"--timeout=30s"}...)
	}

	log.Println("running trivy with args: ", trivyArgs)
	out, err := execCmd("trivy", trivyArgs...).CombinedOutput()
	if err != nil {
		return out, err
	}

	log.Println("trivy returned: ", string(out))
	return out, err
}

func findTrivySep(args []string) int {
	for i, a := range args {
		// trivy args separator is "--"
		if a == "--" {
			if i+1 >= len(args) {
				return -1 // bad case if someone specifies no trivy args
			} else {
				return i + 1 // common case with good args
			}
		}
	}
	return -1 // bad case if no trivy sep & args specified
}

func containsSlice(haystack []string, needle string) bool {
	for _, item := range haystack {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}
