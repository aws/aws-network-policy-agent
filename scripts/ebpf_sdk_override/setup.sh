#!/bin/bash
 
set -e

mkdir -p ./vendor/github.com/aws

SDK_VENDOR_PATH=./vendor/github.com/aws/aws-ebpf-sdk-go

# Clone the SDK to the vendor path (removing an old one if necessary)
rm -rf $SDK_VENDOR_PATH
git clone --depth 1 git@github.com:aws/aws-ebpf-sdk-go.git $SDK_VENDOR_PATH

# Use the vendored version of aws-sdk-go
go mod edit -replace github.com/aws/aws-ebpf-sdk-go=./vendor/github.com/aws/aws-ebpf-sdk-go
go mod tidy
