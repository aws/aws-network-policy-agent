package cp

import (
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-network-policy-agent/pkg/logger"
)

var (
	EKS_CLI_BINARY    = "aws-eks-na-cli"
	EKS_V6_CLI_BINARY = "aws-eks-na-cli-v6"
)

// hostBinaryNames maps binaries to the name they are installed under on the
// host, where it differs. The CLI is always aws-eks-na-cli. The ingress
// binaries that also shorten the conntrack entry of denied connections take
// the regular ingress binary's name, so an agent compares the host copy with
// whichever variant it selected, and an agent without them (after a
// rollback) sees a changed binary and reloads the pods' ingress programs.
var hostBinaryNames = map[string]string{
	EKS_V6_CLI_BINARY:           EKS_CLI_BINARY,
	"tc.v4ingress.ctdeny.bpf.o": "tc.v4ingress.bpf.o",
	"tc.v6ingress.ctdeny.bpf.o": "tc.v6ingress.bpf.o",
}

// HostBinaryName returns the name binary is installed under on the host.
func HostBinaryName(binary string) string {
	if name, ok := hostBinaryNames[binary]; ok {
		return name
	}
	return binary
}

func log() logger.Logger {
	return logger.Get()
}

func cp(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

func CopyFile(src, dst string) (err error) {
	dstTmp := fmt.Sprintf("%s.tmp", dst)
	if err := cp(src, dstTmp); err != nil {
		return fmt.Errorf("failed to copy file: %s", err)
	}

	err = os.Rename(dstTmp, dst)
	if err != nil {
		return fmt.Errorf("failed to rename file: %s", err)
	}

	si, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat file: %s", err)
	}
	err = os.Chmod(dst, si.Mode())
	if err != nil {
		return fmt.Errorf("failed to chmod file: %s", err)
	}

	return nil
}

func InstallBPFBinaries(pluginBins []string, hostCNIBinPath string) error {
	log().Info("Let's install BPF Binaries on to the host path.....")
	for _, plugin := range pluginBins {
		target := fmt.Sprintf("%s%s", hostCNIBinPath, HostBinaryName(plugin))
		source := fmt.Sprintf("%s", plugin)
		log().Infof("Installing BPF Binary..target %s source %s", target, source)

		if err := CopyFile(source, target); err != nil {
			log().Errorf("Failed to install target %s error %v", target, err)
		}
		log().Infof("Successfully installed - binary %s", target)
	}
	return nil
}
