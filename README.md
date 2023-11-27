# trivy-plugin-webhook

## Installation
```shell
trivy plugin install github.com/aquasecurity/trivy-plugin-webhook
```

## Usage
```shell
trivy webhook -- <plugin flags> -- <trivy args>
```

OR

```shell
trivy image YOUR_IMAGE | trivy webhook <plugin flags>
```

OR

```shell
trivy image --output plugin=webhook --output-plugin-arg <plugin flags> YOUR_IMAGE
```

## Examples

```shell
trivy image -f json -o plugin=webhook --output-plugin-arg "--url=http://localhost:8080" debian:12
```

is equivalent to:

```shell
trivy image -f json debian:12 | trivy webhook --url=http://localhost:8080
```

## Command Line Flags

| Flag  | Description | Required | Example                      |
|-------|-------------|----------|------------------------------|
| --url | Webhook URL | Yes      | `--url="http://example.com"` |
