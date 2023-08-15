#!/bin/bash

rm -rf ./vendor
go mod edit -dropreplace github.com/aws/aws-ebpf-sdk-go
go mod tidy
