.PHONY: clean build

clean:
	rm -rf trivy-webhook

build:
	go build -o trivy-webhook .