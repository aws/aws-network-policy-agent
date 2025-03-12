package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const baseDir = "/tmp"
const mapsPath = "/sys/fs/bpf/globals/aws/maps"
const programsPath = "/sys/fs/bpf/globals/aws/programs"
const coreDnsPrefix = "coredns"

func getPodPrefix() string {
	podName := os.Getenv("NODE_NAME")
	if podName == "" {
		log.Println("NODE_NAME environment variable is not set. Cleanup pod filtering may not work correctly.")
		return ""
	}

	// Split by "." to isolate the first part
	parts := strings.SplitN(podName, ".", 2) // Get "ip-192-168-59-7" and ignore the rest
	if len(parts) < 2 {
		log.Printf("Unexpected node name format: %s", podName)
		return ""
	}

	// Replace the first "." with "_" to match the BPF map format
	prefix := strings.Replace(parts[0], ".", "_", 1) + "_"

	log.Printf("Using prefix to ignore cleanup pod maps/programs: %s", prefix)
	return prefix
}

func leakedMapsFound() error {

	if _, err := os.Stat(baseDir + mapsPath); os.IsNotExist(err) {
		log.Printf("Maps directory doesn't exist on the node")
		return nil
	}

	f, err := os.Open(baseDir + mapsPath)
	if err != nil {
		return err
	}
	defer f.Close()

	files, err := f.Readdir(0)
	if err != nil {
		return err
	}

	for _, v := range files {
		if v.Name() != "global_aws_conntrack_map" && v.Name() != "global_policy_events" && !strings.HasPrefix(v.Name(), getPodPrefix()) && !strings.HasPrefix(v.Name(), coreDnsPrefix) {
            return fmt.Errorf("BPF Maps folder is not cleaned up (except conntrack, policy_events, coreDNS): %v", v.Name())
		}
	}

	log.Printf("BPF Maps are cleaned up")
	return nil
}

func leakedProgsFound() error {

	if _, err := os.Stat(baseDir + programsPath); os.IsNotExist(err) {
		log.Printf("Programs directory doesn't exist on the node")
		return nil
	}

	f, err := os.Open(baseDir + programsPath)
	if err != nil {
		return err
	}
	defer f.Close()

	files, err := f.Readdir(0)
	if err != nil {
		return err
	}

	for _, v := range files {
		progName := v.Name()
		// Ignore programs that belong to the cleanup pod
		if !strings.HasPrefix(progName, getPodPrefix()) && !strings.HasPrefix(progName, coreDnsPrefix) {
			return fmt.Errorf("BPF Programs folder is not cleaned up: %v", progName)
		}
	}

	log.Printf("BPF Programs are cleaned up")
	return nil
}

func main() {

	err := leakedMapsFound()
	if err != nil {
		log.Fatal(err)
	}

	err = leakedProgsFound()
	if err != nil {
		log.Fatal(err)
	}
}
