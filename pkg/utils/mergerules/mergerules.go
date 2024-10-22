package mergerules

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
)

// NOTE: First parameter will always be the higher priority. ports/action is higher prioirty than ports2/action2.

func MergePorts(ports, ports2 policyk8sawsv1.Port, action, action2 string, logger logr.Logger) []string {
	logger.Info("Merging ports")
	if string(*ports.Protocol) == "ALL" && string(*ports2.Protocol) == "ALL" {
		return mergeGlobalIPs(ports, ports2, action, action2)
	}
	if string(*ports.Protocol) == "ALL" {
		return mergeGlobalIPPorts(ports, ports2, action, action2)
	}
	if string(*ports2.Protocol) == "ALL" {
		return mergeGlobalPortsIP(ports, ports2, action, action2)
	}
	return mergeGlobalPorts(ports, ports2, action, action2, logger)
}

func mergeGlobalIPs(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	if action == action2 || action == "Allow" {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, 0, 0)}
	}
	return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, 0, 0)}
}

func mergeGlobalIPPorts(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	if ports2.EndPort == nil {
		zero := int32(0)
		ports2.EndPort = &zero
	}
	if action == action2 {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, 0, 0)}
	}
	if action == "Allow" {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, 0, 0),
			fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
	}
	return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, 0, 0)}
}

func mergeGlobalPortsIP(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	zero := int32(0)
	if ports.EndPort == nil {
		ports.EndPort = &zero
	}
	if action == action2 || action == "Allow" {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, 0, 0)}
	}
	return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
		fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, 0, 0)}
}

func mergeGlobalPorts(ports, ports2 policyk8sawsv1.Port, action, action2 string, logger logr.Logger) []string {
	portRange := isRange(ports)
	portRange2 := isRange(ports2)
	if portRange && portRange2 {
		if action == action2 {
			startPort := math.Min(float64(*ports.Port), float64(*ports2.Port))
			endPort := math.Max(float64(*ports.EndPort), float64(*ports2.EndPort))
			return []string{fmt.Sprintf("%s-%s-%f-%f", action, *ports.Protocol, startPort, endPort)}
		} else if action == "Allow" {
			if *ports2.Port <= *ports.Port && *ports2.EndPort >= *ports.EndPort {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
			}
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
		} else {
			if *ports.Port > *ports2.Port && *ports.EndPort < *ports2.EndPort {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
					fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports.EndPort-1),
					fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports.EndPort+1, *ports2.EndPort)}
			} else if *ports.Port <= *ports2.Port && *ports.EndPort >= *ports2.EndPort {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
			} else if *ports.Port <= *ports2.Port && *ports.EndPort < *ports2.EndPort {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
					fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports.EndPort+1, *ports2.EndPort)}
			}
			// Case: *ports.Port >= *ports2.Port && *ports.EndPort > *ports2.EndPort
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports.Port-1)}
		}
	} else if portRange {
		if action == action2 {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		} else if action == "Allow" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, 0)}
		}
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
	} else if portRange2 {
		if action == action2 {
			// return the portrange portrange2
			return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, 0)}
		} else if action == "Allow" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, 0)}
		} else if action == "Pass" {
			if ports.Port == ports2.Port {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port+1, *ports2.EndPort)}
			} else if ports.Port == ports2.EndPort {
				return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort-1)}
			}
			return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports.Port-1),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports.Port+1, *ports2.EndPort)}
		} else {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports.Protocol, *ports.Port, 0),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
		}
	}
	// Case where neither are port ranges
	if action == action2 {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, 0)}
	} else if action == "Allow" {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, 0)}
	}
	return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, 0)}
}

func MergeGlobalLocalPorts(global []string, local []string) []string {
	for _, loc := range local {
		localSplit := strings.Split(loc, "-")
		localPortInt, _ := strconv.Atoi(localSplit[2])
		localPrt := int32(localPortInt)
		localEndportInt, _ := strconv.Atoi(localSplit[3])
		localEndport := int32(localEndportInt)
		localPort := policyk8sawsv1.Port{
			Protocol: (*v1.Protocol)(&localSplit[1]),
			Port:     &localPrt,
			EndPort:  &localEndport,
		}
		for _, glo := range global {
			globalSplit := strings.Split(glo, "-")
			globalPortInt, _ := strconv.Atoi(globalSplit[2])
			globalPrt := int32(globalPortInt)
			globalEndportInt, _ := strconv.Atoi(globalSplit[3])
			globalEndport := int32(globalEndportInt)
			globalPort := policyk8sawsv1.Port{
				Protocol: (*v1.Protocol)(&globalSplit[1]),
				Port:     &globalPrt,
				EndPort:  &globalEndport,
			}
			if localSplit[1] == "ALL" && globalSplit[1] == "ALL" {
				return mergeGlobalIPLocalIPs(globalPort, localPort, globalSplit[0], localSplit[0])
			} else if localSplit[1] == "ALL" {
				return mergeGlobalPortsLocalIPs(globalPort, localPort, globalSplit[0], localSplit[0])
			} else if globalSplit[1] == "ALL" {
				return mergeGlobalIPLocalPorts(globalPort, localPort, globalSplit[0], localSplit[0])
			} else {
				return mergeGlobalPortsLocalPorts(globalPort, localPort, globalSplit[0], localSplit[0])
			}
		}
	}
	return nil
}

func mergeGlobalIPLocalIPs(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	if action == action2 {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
	}
	if action == "Allow" {
		if action2 == "Deny" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		}
	} else if action == "Deny" {
		if action2 == "Allow" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		}
	}
	return nil
}

func mergeGlobalIPLocalPorts(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	if action == action2 {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
	}
	if action == "Allow" {
		if action2 == "Deny" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		}
	} else if action == "Deny" {
		if action2 == "Allow" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		}
	}
	return nil
}

func mergeGlobalPortsLocalIPs(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	zero := int32(0)
	if ports2.EndPort == nil {
		ports2.EndPort = &zero
	}
	if ports.EndPort == nil {
		ports.EndPort = &zero
	}
	if action == action2 {
		return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
	}
	if action == "Allow" {
		if action2 == "Deny" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
		}
	} else if action == "Deny" {
		if action2 == "Allow" {
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort),
				fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
		}
	}
	return nil
}

func mergeGlobalPortsLocalPorts(ports, ports2 policyk8sawsv1.Port, action, action2 string) []string {
	portRange := isRange(ports)
	portRange2 := isRange(ports2)
	if portRange && portRange2 {
		//TODO
		if action == action2 {

		}
	} else if portRange {
		if action == action2 {
			// return the portrange portrange
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		} else if action == "Allow" {
			// append deny port
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
		} else {
			if action2 == "Allow" {
				//return deny port range
				return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, *ports.EndPort)}
			}
		}
	} else if portRange2 {
		if action == action2 {
			// return the portrange portrange2
			return []string{fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, 0)}
		} else if action == "Deny" {
			if action2 == "Allow" {
				// append deny
				return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, 0),
					fmt.Sprintf("%s-%s-%d-%d", action2, *ports2.Protocol, *ports2.Port, *ports2.EndPort)}
			}
		}
	} else {
		if action == action2 {
			//do nothing
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, 0)}
		} else if action == "Deny" {
			// Do nothing
			return []string{fmt.Sprintf("%s-%s-%d-%d", action, *ports.Protocol, *ports.Port, 0)}
		}
	}
	return nil
}

func isRange(ports policyk8sawsv1.Port) bool {
	return ports.EndPort != nil
}
