# Casbin Service

This is the Casbin service

Generated with

```
micro new github.com/cicdi-go/casbin --namespace=go.micro --type=srv
```

## Getting Started

- [Configuration](#configuration)
- [Dependencies](#dependencies)
- [Usage](#usage)

## Configuration

- FQDN: go.micro.srv.casbin
- Type: srv
- Alias: casbin

## Dependencies

Micro services depend on service discovery. The default is consul.

```
# install consul
brew install consul

# run consul
consul agent -dev
```

## Usage

A Makefile is included for convenience

Build the binary

```
make build
```

Run the service
```
./casbin-srv
```

Build a docker image
```
make docker
```