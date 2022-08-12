package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func fakeExecCmdFailure(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestShellProcessFail", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_TEST_PROCESS=1"}
	return cmd
}

func TestShellProcessFail(t *testing.T) {
	if os.Getenv("GO_TEST_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stderr, "failure")
	os.Exit(1)
}

func fakeExecCmdSuccess(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestShellProcessSuccess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_TEST_PROCESS=1"}
	return cmd
}

func TestShellProcessSuccess(t *testing.T) {
	if os.Getenv("GO_TEST_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stderr, "success")
	os.Exit(0)
}

func Test_runScan(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		got, err := runScan([]string{"./trivy-webhook", "--", "image", "alpine:3.10", "--timeout=30s"}, fakeExecCmdSuccess)
		assert.NoError(t, err)
		assert.Equal(t, "success", string(got))
	})

	t.Run("sad path, no trivy args separator found", func(t *testing.T) {
		got, err := runScan([]string{"./trivy-webhook", "image", "alpine:3.10"}, fakeExecCmdSuccess)
		assert.Equal(t, "invalid arguments specified", err.Error())
		assert.Equal(t, "", string(got))
	})

	t.Run("sad path, trivy fails to run", func(t *testing.T) {
		got, err := runScan([]string{"./trivy-webhook", "--", "image", "alpine:3.10"}, fakeExecCmdFailure)
		assert.Equal(t, "exit status 1", err.Error())
		assert.Equal(t, "failure", string(got))
	})
}

func Test_findTrivySep(t *testing.T) {
	testCases := []struct {
		name             string
		inputArgs        []string
		expectedSepIndex int
	}{
		{
			name:             "happy path",
			inputArgs:        []string{"./trivy-webhook", "--", "image", "alpine:3.10"},
			expectedSepIndex: 2,
		},
		{
			name:             "sad path, no separator",
			inputArgs:        []string{"./trivy-webhook", "image", "alpine:3.10"},
			expectedSepIndex: -1,
		},
		{
			name:             "sad path, separator found but no trivy args",
			inputArgs:        []string{"./trivy-webhook", "--"},
			expectedSepIndex: -1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedSepIndex, findTrivySep(tc.inputArgs), tc.name)
		})
	}
}

func Test_sendToWebhook(t *testing.T) {

	t.Run("happy path", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "webhook success")
		}))
		defer ts.Close()

		resp, err := sendToWebhook(ts.URL, &http.Client{Timeout: time.Second * 30}, []byte("foo bar baz"))
		require.NoError(t, err)
		assert.Equal(t, "webhook success", string(resp))
	})

	t.Run("sad path, webhook times out", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(time.Second)
		}))
		defer ts.Close()

		resp, err := sendToWebhook(ts.URL, &http.Client{Timeout: time.Microsecond}, []byte("foo bar baz"))
		assert.Contains(t, err.Error(), "deadline exceeded")
		assert.Empty(t, resp)
	})
}
