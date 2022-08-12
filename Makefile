.PHONY: clean build test

clean:
	rm -rf trivy-webhook

build:
	go build -o trivy-webhook .

test:
	go test -race -v ./...