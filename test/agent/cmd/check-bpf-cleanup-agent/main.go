package main

import (
    "fmt"
    "log"
    "os"
)

const baseDir = "/tmp"
const mapsPath = "/sys/fs/bpf/globals/aws/maps"
const programsPath = "/sys/fs/bpf/globals/aws/programs"

func areMapsCleaned() error {

    if _, err:= os.Stat(baseDir + mapsPath); os.IsNotExist(err) {
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
        if v.Name() != "global_aws_conntrack_map" && v.Name() != "global_policy_events" {
            return fmt.Errorf("BPF Maps folder is not cleaned up (except conntrack, policy_events): %v", v.Name())
        }
    }

    log.Printf("BPF Maps are cleaned up")
    return nil
}

func areProgramsCleaned() error {

    if _, err := os.Stat(baseDir+programsPath); os.IsNotExist(err) {
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

    if len(files) > 0 {
        return fmt.Errorf("BPF Programs folder is not cleaned up")
    }

    log.Printf("BPF Programs are cleaned up")
    return nil
}

func main() {

    err := areMapsCleaned()
    if err != nil {
        log.Fatal(err)
    }

    err = areProgramsCleaned()
    if err != nil {
        log.Fatal(err)
    }
}
