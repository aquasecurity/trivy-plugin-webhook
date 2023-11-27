package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		slog.Error("Unexpected error", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func run() error {
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
		return errors.New("trivy webhook plugin expects a webhook endpoint url")
	}

	var out io.Reader
	if flag.NArg() == 0 || (flag.NArg() == 1 && flag.Arg(0) == "-") {
		slog.Info("Reading scanning results from stdin...")
		out = os.Stdin
	} else {
		slog.Info("Running trivy...")
		b, err := runScan(os.Args, exec.Command)
		if err != nil {
			flag.Usage()
			return fmt.Errorf("trivy returned an error: %w, output: %s", err, string(b))
		}
		out = bytes.NewBuffer(b)
	}

	slog.Info("Sending results to webhook...")
	resp, err := sendToWebhook(*webhookUrl, &http.Client{
		Timeout: time.Second * 30,
	}, out)
	if err != nil {
		return fmt.Errorf("failed to send to webhook: %w", err)
	}

	slog.Info("webhook returned", slog.String("response", string(resp)))
	return nil
}

func sendToWebhook(webhookUrl string, client *http.Client, body io.Reader) ([]byte, error) {
	resp, err := client.Post(webhookUrl, "application/json", body)
	if err != nil {
		return nil, fmt.Errorf("failed to build post request: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
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
	trivyArgs = append(trivyArgs, []string{"--quiet", "--timeout=30s"}...)

	slog.Info("Running trivy", slog.String("args", strings.Join(trivyArgs, " ")))
	out, err := execCmd("trivy", trivyArgs...).CombinedOutput()
	if err != nil {
		return out, err
	}

	slog.Info("trivy returned", slog.String("response", string(out)))
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
