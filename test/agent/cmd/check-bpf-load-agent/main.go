// check-bpf-load-agent loads the network policy agent's ingress BPF objects on
// this node's kernel and reports which ones load. The agent uses only one
// ingress object per node (the ct-deny one where the kernel has the
// nf_conntrack kfuncs, the regular one otherwise), so on a node with the kfuncs
// nothing else would ever load the regular object. Running this on every node
// in the kernel matrix keeps both objects covered.
//
// It runs in a privileged pod that shares the host's PID namespace and bpffs.
// It copies the objects out of the running agent's container, so it checks the
// objects the agent ships rather than copies built into this image, and loads
// each against the node's global maps under a throwaway pin prefix, which it
// removes afterwards.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-ebpf-sdk-go/pkg/btf"
	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	"golang.org/x/sys/unix"
)

const (
	// No "_": the SDK takes everything before a pin name's first "_" as its
	// prefix, and would treat the per-pod maps as global ones otherwise.
	pinPrefix   = "LOADCHECK"
	programsDir = "/sys/fs/bpf/globals/aws/programs/"
	mapsDir     = "/sys/fs/bpf/globals/aws/maps/"
	// The agent's binary in its container, used to find the agent process.
	agentBinary = "/controller"
)

// The kfuncs the ct-deny objects call, as in pkg/ebpf/bpf_client.go.
var ctDenyKfuncs = []string{"bpf_skb_ct_lookup", "bpf_ct_change_timeout", "bpf_ct_release"}

// The agent's per-pod maps, as in utils.NamespacedBPFMaps. The SDK treats any
// other map name as global.
var namespacedMaps = []string{
	"ingress_map", "egress_map", "cp_ingress_map", "cp_egress_map",
	"ingress_pod_state_map", "egress_pod_state_map",
}

func main() {
	family := flag.String("family", "v4", "IP family of the cluster: v4 or v6")
	flag.Parse()
	objects := []string{"tc.v4ingress.bpf.o", "tc.v4ingress.ctdeny.bpf.o"}
	if *family == "v6" {
		objects = []string{"tc.v6ingress.bpf.o", "tc.v6ingress.ctdeny.bpf.o"}
	}

	if err := btf.CheckKfuncs(ctDenyKfuncs); err != nil {
		fmt.Printf("KFUNCS absent: %v\n", err)
	} else {
		fmt.Println("KFUNCS present")
	}

	root, err := agentRoot()
	if err != nil {
		fmt.Printf("ERROR %v\n", err)
		os.Exit(1)
	}

	client := goelf.New(goelf.Config{NamespacedMaps: namespacedMaps})
	// The ingress objects reference the global maps the agent created. Recovering
	// them puts their FDs in the SDK's map cache, which the loads relocate against.
	if _, err := client.RecoverGlobalMaps(); err != nil {
		fmt.Printf("ERROR recovering global maps: %v\n", err)
		os.Exit(1)
	}

	failed := false
	for _, obj := range objects {
		local := filepath.Join(os.TempDir(), obj)
		if err := copyFile(filepath.Join(root, obj), local); err != nil {
			fmt.Printf("LOAD %s ERROR copying from the agent: %v\n", obj, err)
			failed = true
			continue
		}
		removePins()
		progs, maps, err := client.LoadBpfFile(local, pinPrefix)
		for _, p := range progs {
			closeFD(p.Program.ProgFD)
		}
		for _, m := range maps {
			closeFD(int(m.MapFD))
		}
		removePins()
		if err != nil {
			fmt.Printf("LOAD %s FAIL %v\n", obj, err)
			continue
		}
		fmt.Printf("LOAD %s OK\n", obj)
	}
	if failed {
		os.Exit(1)
	}
}

// agentRoot returns the agent container's root filesystem, as seen through
// /proc from the host's PID namespace.
func agentRoot() (string, error) {
	procs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		return "", err
	}
	for _, c := range procs {
		b, err := os.ReadFile(c)
		if err != nil || len(b) == 0 {
			continue
		}
		if strings.SplitN(string(b), "\x00", 2)[0] == agentBinary {
			return filepath.Join(filepath.Dir(c), "root"), nil
		}
	}
	return "", errors.New("network policy agent process not found; is the pod running with hostPID?")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// removePins removes the programs and maps pinned under pinPrefix.
func removePins() {
	for _, dir := range []string{programsDir, mapsDir} {
		pins, _ := filepath.Glob(dir + pinPrefix + "_*")
		for _, pin := range pins {
			if err := os.Remove(pin); err != nil && !os.IsNotExist(err) {
				fmt.Printf("WARN removing %s: %v\n", pin, err)
			}
		}
	}
}

func closeFD(fd int) {
	if fd > 0 {
		unix.Close(fd)
	}
}
