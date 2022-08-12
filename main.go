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
)

func findTrivySep(args []string) int {
	for i, a := range args {
		// trivy args separator is "--"
		if a == "--" {
			if i+1 > len(args) {
				return -1 // bad case if someone specifies no trivy args
			} else {
				return i + 1 // common case with good args
			}
		}
	}
	return -1 // bad case if no trivy sep & args specified
}

func main() {
	webhookUrl := flag.String("url", "", "webhook endpoint url")
	flag.Parse()

	if len(*webhookUrl) <= 0 {
		flag.Usage()
		log.Fatal("trivy webhook plugin expects a webhook endpoint url")
	}

	log.Println("running trivy...")
	out, err := runScan()
	if err != nil {
		log.Fatal("trivy returned an error: ", err, "output: ", string(out))
	}

	log.Println("sending results to webhook...")
	resp, err := sendToWebhook(webhookUrl, out)
	if err != nil {
		log.Fatal("failed to send to webhook: ", err)
	}

	log.Println("webhook returned: ", string(resp))
}

func sendToWebhook(webhookUrl *string, out []byte) ([]byte, error) {
	resp, err := http.Post(*webhookUrl, "application/json", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("failed to build post request: %s", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %s", err)
	}

	return b, nil
}

func runScan() ([]byte, error) {
	trivyArgsIndex := findTrivySep(os.Args)
	trivyArgs := os.Args[trivyArgsIndex:]
	trivyArgs = append(trivyArgs, []string{"--format=json", "--quiet", "--timeout=30s"}...)

	log.Println("running trivy with args: ", trivyArgs)
	out, err := exec.Command("trivy", trivyArgs...).CombinedOutput()
	if err != nil {
		return out, err
	}

	log.Println("trivy returned: ", string(out))
	return out, err
}
