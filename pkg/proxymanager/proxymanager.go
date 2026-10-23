package proxymanager

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/avast/retry-go"
	cdnsproxy "github.com/aws/aws-network-policy-agent/pkg/cdns-proxy"
	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/aws/aws-network-policy-agent/pkg/filter"
	"github.com/aws/aws-network-policy-agent/pkg/logger"
	npatypes "github.com/aws/aws-network-policy-agent/pkg/types"
	"github.com/aws/aws-network-policy-agent/pkg/utils"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// NFT_TABLE_NAME defines the nftables table name for DNS redirection
	NFT_TABLE_NAME = "dns_redirect"
	// NFT_CHAIN_NAME defines the nftables chain name for DNS redirection
	NFT_CHAIN_NAME = "prerouting"
	// DNSPROXY_INTERFACE_NAME defines the name of the dnsproxy interface
	DNSPROXY_INTERFACE_NAME = "dnsproxy"
	// NftChainPriority places the DNS redirect DNAT ahead of kube-proxy's Service DNAT (-100) and of the
	// native nftables kube-proxy pre-DNAT filter (-110), so a pod's query to the kube-dns Service IP is
	// redirected before kube-proxy rewrites it. EKS Auto Mode uses -100.
	NftChainPriority = -120
)

/*
This proxy manager will be responsible for
- starting dnsproxy
- adding/deleting DNS redirection rules per pod for routing DNS traffic to the dns proxy

TODO
- Implement garbage collection for ip_cache map
- Refactor to move out NF table related code out and add UT for this proxy manager
*/

type ProxyManager interface {
	AddDNSRedirectionRulesForPod(pod npatypes.Pod, podIdentifier string) error
	RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error
	ForceRemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error
	HealthCheckDNSProxy() error
}

type proxyManager struct {
	log          logger.Logger
	ebpfClient   ebpf.BpfClient
	upstreamIP   net.IP
	upstreamPort int
	listenerIP   net.IP
	listenerPort int
	npMode       string
	// this map stores the actual nftables rules for each pod for deletion and idempotency checks
	podRules sync.Map // map[string][]*nftables.Rule
	// this map stores the pod IP for each pod (used for cleanup during force removal)
	podIPMap sync.Map // map[string]string (podKey -> podIP)
	// per-pod locks to prevent race conditions
	podLocks sync.Map // map[string]*sync.Mutex
	// nftables connection and references
	nftConn  *nftables.Conn
	nftTable *nftables.Table
	nftChain *nftables.Chain
	initOnce sync.Once
	// DNS proxy state management
	dnsProxyStarted  atomic.Bool
	dnsProxyStartMux sync.Mutex
	dnsProxyFailed   atomic.Uint64
}

// NewProxyManager returns a ProxyManager for an IPv4 node.
func NewProxyManager(log logger.Logger, ebpfClient ebpf.BpfClient, upstreamIP net.IP, upstreamPort int, listenerIP net.IP, listenerPort int, npMode string) ProxyManager {
	return &proxyManager{
		log:          log,
		ebpfClient:   ebpfClient,
		upstreamIP:   upstreamIP,
		upstreamPort: upstreamPort,
		listenerIP:   listenerIP,
		listenerPort: listenerPort,
		npMode:       npMode,
	}
}

// startDNSProxy starts the DNS proxy if it hasn't been started yet
// This is called lazily when the first pod needs DNS redirection
// If startup fails, subsequent calls will retry the startup
func (pm *proxyManager) startDNSProxy() error {
	// Fast path: check if already started successfully
	if pm.dnsProxyStarted.Load() {
		return nil
	}

	// Acquire lock to ensure only one goroutine attempts startup at a time
	pm.dnsProxyStartMux.Lock()
	defer pm.dnsProxyStartMux.Unlock()

	// Double-check after acquiring lock (another goroutine might have succeeded)
	if pm.dnsProxyStarted.Load() {
		return nil
	}

	startTime := time.Now()
	pm.log.Info("Starting DNS proxy...")

	// Set up the dnsproxy interface and assign the listener IP
	if err := pm.setupDNSProxyInterface(); err != nil {
		pm.log.Errorf("failed to setup DNSProxy interface: %v", err)
		return fmt.Errorf("failed to setup DNSProxy interface: %w", err)
	}

	if err := pm.addListenerIPToInterface(); err != nil {
		pm.log.Errorf("failed to add listener IP to DNSProxy interface: %v", err)
		return fmt.Errorf("failed to add listener IP to DNSProxy interface: %w", err)
	}

	// Initialize nftables setup
	if err := pm.initNftables(); err != nil {
		pm.log.Errorf("failed to initialize nftables: %v", err)
		return fmt.Errorf("failed to initialize nftables: %w", err)
	}

	if err := pm.startCDNSProxy(context.Background(), pm.log, pm.ebpfClient); err != nil {
		return err
	}

	// Perform health check with retries
	if err := pm.checkDNSProxyHealth(); err != nil {
		return fmt.Errorf("dns proxy health check failed: %w", err)
	}

	// Only mark as started if everything succeeded
	pm.dnsProxyStarted.Store(true)
	elapsedTime := time.Since(startTime)
	pm.log.Infof("DNS proxy started successfully in %v", elapsedTime)

	return nil
}

func (pm *proxyManager) startCDNSProxy(ctx context.Context, log logger.Logger, ebpfClient ebpf.BpfClient) error {
	// Format addresses for corefile content
	upstreamAddrStr := fmt.Sprintf("%s:%d", pm.upstreamIP.String(), pm.upstreamPort)
	listenerAddrStr := fmt.Sprintf("%s:%d", pm.listenerIP.String(), pm.listenerPort)
	pm.log.Infof("upstreamAddr: %s listenerAddr: %s", upstreamAddrStr, listenerAddrStr)

	// Health endpoint uses listenerIP with listenerPort+1
	healthEndpoint := fmt.Sprintf("%s:%d", pm.listenerIP.String(), pm.listenerPort+1)

	corefileContent := fmt.Sprintf(`.:%d {
	bind %s
	health %s
	log . {
      class denial error
    }
	ipfilter
	forward . %s
}`, pm.listenerPort, pm.listenerIP.String(), healthEndpoint, upstreamAddrStr)

	if err := cdnsproxy.NewDNSProxy(log, ebpfClient, upstreamAddrStr, listenerAddrStr).Start(ctx, corefileContent); err != nil {
		return fmt.Errorf("error in starting DNS proxy %w", err)
	}

	return nil
}

// setupDNSProxyInterface creates the dnsproxy interface using netlink if it doesn't exist
func (pm *proxyManager) setupDNSProxyInterface() error {
	// Check if interface already exists
	link, err := netlink.LinkByName(DNSPROXY_INTERFACE_NAME)
	if err != nil {
		// Interface doesn't exist, create it
		pm.log.Infof("DNSProxy interface does not exist, creating new one...")

		// Create a dummy interface
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: DNSPROXY_INTERFACE_NAME,
			},
		}

		if err := netlink.LinkAdd(dummy); err != nil {
			return fmt.Errorf("failed to create DNSProxy interface: %w", err)
		}

		// Get the newly created link
		link, err = netlink.LinkByName(DNSPROXY_INTERFACE_NAME)
		if err != nil {
			return fmt.Errorf("failed to get DNSProxy interface after creation: %w", err)
		}
	}

	// Bring the interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up DNSProxy interface: %w", err)
	}

	pm.log.Infof("DNSProxy interface %s is ready", DNSPROXY_INTERFACE_NAME)
	return nil
}

// addListenerIPToInterface adds the listener IP to the dnsproxy interface using netlink
func (pm *proxyManager) addListenerIPToInterface() error {
	// Get the interface
	link, err := netlink.LinkByName(DNSPROXY_INTERFACE_NAME)
	if err != nil {
		return fmt.Errorf("failed to get DNSProxy interface: %w", err)
	}

	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   pm.listenerIP,
			Mask: net.CIDRMask(32, 32),
		},
	}

	// Add the address to the interface
	err = netlink.AddrAdd(link, addr)
	if err != nil {
		// Check if the address already exists
		if err.Error() == "file exists" {
			pm.log.Infof("IP address %s already exists on %s interface", pm.listenerIP.String(), DNSPROXY_INTERFACE_NAME)
			return nil
		}
		return fmt.Errorf("failed to add IP address %s to %s interface: %w", pm.listenerIP.String(), DNSPROXY_INTERFACE_NAME, err)
	}

	pm.log.Infof("Successfully added IP address %s to %s interface", pm.listenerIP.String(), DNSPROXY_INTERFACE_NAME)
	return nil
}

// initNftables initializes the nftables table and chain for DNS redirection
func (pm *proxyManager) initNftables() error {
	var err error
	pm.initOnce.Do(func() {
		pm.nftConn = &nftables.Conn{}

		tableFamily := nftables.TableFamilyIPv4
		tableName := "ip " + NFT_TABLE_NAME
		pm.log.Infof("Initializing IPv4 nftables table: %s", tableName)

		// Check if table already exists
		tables, listErr := pm.nftConn.ListTables()
		if listErr != nil {
			pm.log.Warnf("Failed to list existing nftables tables: %v", listErr)
		} else {
			for _, table := range tables {
				if table.Name == NFT_TABLE_NAME && table.Family == tableFamily {
					pm.log.Infof("Table %s already exists, cleaning all rules", tableName)
					// Delete the existing table (this removes all chains and rules)
					pm.nftConn.DelTable(table)
					if flushErr := pm.nftConn.Flush(); flushErr != nil {
						pm.log.Warnf("Failed to delete existing table: %v", flushErr)
					} else {
						pm.log.Infof("Successfully cleaned existing table %s", tableName)
					}
					break
				}
			}
		}

		// Create table with appropriate family
		pm.nftTable = pm.nftConn.AddTable(&nftables.Table{
			Family: tableFamily,
			Name:   NFT_TABLE_NAME,
		})

		// Create prerouting chain
		pm.log.Infof("Using nftables %s chain priority %d", NFT_CHAIN_NAME, NftChainPriority)
		pm.nftChain = pm.nftConn.AddChain(&nftables.Chain{
			Name:     NFT_CHAIN_NAME,
			Table:    pm.nftTable,
			Type:     nftables.ChainTypeNAT,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(NftChainPriority)),
		})

		// Flush the initial setup
		err = pm.nftConn.Flush()
		if err != nil {
			pm.log.Errorf("Failed to initialize nftables: %v", err)
		} else {
			pm.log.Infof("Successfully initialized nftables table and chain for %s", tableName)
		}
	})
	return err
}

// getPodLock gets or creates a mutex for the given pod
func (pm *proxyManager) getPodLock(podKey string) *sync.Mutex {
	lockInterface, _ := pm.podLocks.LoadOrStore(podKey, &sync.Mutex{})
	return lockInterface.(*sync.Mutex)
}

// AddDNSRedirectionRulesForPod adds nftables rules for a specific pod's veth interface
func (pm *proxyManager) AddDNSRedirectionRulesForPod(pod npatypes.Pod, podIdentifier string) error {
	// Start DNS proxy if not already started
	if !pm.dnsProxyStarted.Load() {
		if err := pm.startDNSProxy(); err != nil {
			pm.dnsProxyFailed.Add(1)
			return fmt.Errorf("failed to start DNS proxy: %w", err)
		}
	}

	// Get the lock for this pod to prevent race conditions
	podLock := pm.getPodLock(pod.String())
	podLock.Lock()
	defer podLock.Unlock()

	// Check if rules already exist for this pod (idempotency check under lock)
	if _, exists := pm.podRules.Load(pod.String()); exists {
		pm.log.Debugf("nftables rules already exist for pod %s, skipping", pod.NamespacedName.String())
		return nil
	}

	hostVethName, err := utils.GetHostVethName(pod.Name, pod.Namespace, 0, []string{ebpf.POD_VETH_PREFIX, ebpf.BRANCH_ENI_VETH_PREFIX})
	if err != nil {
		pm.log.Warnf("Failed to get veth name for pod %s in namespace %s. Pod might have been deleted", pod.Name, pod.Namespace)
		return err
	}

	podIP := string(pod.PodIP)
	if podIP == "" {
		// A CNI ADD carries no pod IP; the CNI plugin has already routed the pod IP to its host veth
		if podIP, err = podIPOfHostVeth(hostVethName); err != nil {
			return err
		}
	}
	filter.SetPodIPToPodId(podIP, podIdentifier)
	pm.podIPMap.Store(pod.NamespacedName.String(), podIP)

	// Add nftables rules for IPv4 and store rule references
	rules, err := pm.addNftRulesForInterface(hostVethName)
	if err != nil {
		return fmt.Errorf("failed to add nftables rules: %w", err)
	}

	pm.podRules.Store(pod.String(), rules)
	pm.log.Infof("Added nftables rules for pod %s with veth interface %s", pod.NamespacedName.String(), hostVethName)

	return nil
}

// podIPOfHostVeth returns the pod IPv4 address the CNI plugin routes to hostVethName.
func podIPOfHostVeth(hostVethName string) (string, error) {
	link, err := netlink.LinkByName(hostVethName)
	if err != nil {
		return "", fmt.Errorf("failed to get host veth %s: %w", hostVethName, err)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("failed to list routes of host veth %s: %w", hostVethName, err)
	}
	podIP := hostRouteIP(routes)
	if podIP == "" {
		return "", fmt.Errorf("no /32 route to a pod IP on host veth %s", hostVethName)
	}
	return podIP, nil
}

// hostRouteIP returns the destination of the first /32 route, which is the pod IP on a pod host veth.
func hostRouteIP(routes []netlink.Route) string {
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		if ones, bits := route.Dst.Mask.Size(); ones == 32 && bits == 32 {
			return route.Dst.IP.String()
		}
	}
	return ""
}

// addNftRulesForInterface adds nftables rules for DNS traffic redirection for a specific interface
func (pm *proxyManager) addNftRulesForInterface(interfaceName string) ([]*nftables.Rule, error) {
	pm.log.Infof("Adding nftables rules for interface %s", interfaceName)

	destAddr := pm.listenerIP.To4()
	natFamily := uint32(nftables.TableFamilyIPv4)
	protocolOffset := uint32(9) // Protocol field offset in IPv4 header

	// UDP rule
	udpRule := &nftables.Rule{
		Table: pm.nftTable,
		Chain: pm.nftChain,
		Exprs: []expr.Any{
			// Match specific interface
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(interfaceName),
			},
			// Match UDP protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       protocolOffset,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_UDP},
			},
			// Match destination port 53
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0, 53},
			},
			// DNAT
			&expr.Immediate{
				Register: 1,
				Data:     destAddr,
			},
			&expr.Immediate{
				Register: 2,
				Data:     []byte{uint8(pm.listenerPort >> 8), uint8(pm.listenerPort & 0xff)},
			},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      natFamily,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	}

	// TCP rule
	tcpRule := &nftables.Rule{
		Table: pm.nftTable,
		Chain: pm.nftChain,
		Exprs: []expr.Any{
			// Match specific interface
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(interfaceName),
			},
			// Match TCP protocol
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       protocolOffset,
				Len:          1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_TCP},
			},
			// Match destination port 53
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2,
				Len:          2,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0, 53},
			},
			// DNAT
			&expr.Immediate{
				Register: 1,
				Data:     destAddr,
			},
			&expr.Immediate{
				Register: 2,
				Data:     []byte{uint8(pm.listenerPort >> 8), uint8(pm.listenerPort & 0xff)},
			},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      natFamily,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	}

	pm.nftConn.AddRule(udpRule)
	pm.nftConn.AddRule(tcpRule)

	// Flush changes to commit rules to kernel
	if err := pm.nftConn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to flush nftables changes: %w", err)
	}

	// Get the rules from the kernel with their assigned handles
	chainRules, err := pm.nftConn.GetRules(pm.nftTable, pm.nftChain)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from kernel: %w", err)
	}

	// Find our rules by matching the interface name in the rule expressions
	var addedRules []*nftables.Rule
	for _, rule := range chainRules {
		if pm.ruleMatchesInterface(rule, interfaceName) {
			addedRules = append(addedRules, rule)
		}
	}

	if len(addedRules) == 0 {
		pm.log.Warnf("Could not find added rules for interface %s in kernel", interfaceName)
		// Return empty slice rather than error to avoid breaking the flow
		return []*nftables.Rule{}, nil
	}

	pm.log.Infof("Successfully added %d nftables rules for interface %s", len(addedRules), interfaceName)
	return addedRules, nil
}

// ruleMatchesInterface checks if a rule matches the given interface name
func (pm *proxyManager) ruleMatchesInterface(rule *nftables.Rule, interfaceName string) bool {
	// Look for Meta expression with IIFNAME key followed by Cmp expression with interface name
	for i, expression := range rule.Exprs {
		if meta, ok := expression.(*expr.Meta); ok && meta.Key == expr.MetaKeyIIFNAME {
			// Check if the next expression is a comparison with our interface name
			if i+1 < len(rule.Exprs) {
				if cmp, ok := rule.Exprs[i+1].(*expr.Cmp); ok && cmp.Op == expr.CmpOpEq {
					// Compare the data (interface name)
					if string(cmp.Data) == interfaceName {
						return true
					}
				}
			}
		}
	}
	return false
}

// RemoveIPTableRulesForPod removes DNS redirection rules for a pod if no controller has domain rules
// This is called by controllers during policy reconciliation
// It checks if any controller still has domain rules for the podIdentifier before removing
func (pm *proxyManager) RemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	// Get the lock for this pod to prevent race conditions
	podLock := pm.getPodLock(pod.String())
	podLock.Lock()
	defer podLock.Unlock()

	if filter.HasAnyDomainRules(podIdentifier) {
		pm.log.Infof("Domain rules still exist for podIdentifier %s from other controllers, skipping DNS redirection rule removal for pod %s",
			podIdentifier, pod.String())
		return nil // Early return - don't remove rules yet
	}

	return pm.removeNFTableRulesInternal(pod)
}

// ForceRemoveIPTableRulesForPod unconditionally removes DNS redirection rules and cleans up all mappings
// This is called by the RPC handler when a pod is being deleted
// It does not check for domain rules and always performs cleanup
func (pm *proxyManager) ForceRemoveDNSRedirectionRulesForPod(pod types.NamespacedName, podIdentifier string) error {
	podLock := pm.getPodLock(pod.String())
	podLock.Lock()
	defer podLock.Unlock()

	podKey := pod.String()
	pm.log.Infof("ForceRemoveIPTableRulesForPod called for pod %s (podIdentifier: %s) - unconditional removal", podKey, podIdentifier)

	// Lookup pod IP from our internal map
	var podIP string
	if podIPInterface, exists := pm.podIPMap.Load(podKey); exists {
		podIP = podIPInterface.(string)
		pm.log.Debugf("Found pod IP %s for pod %s", podIP, podKey)
	} else {
		pm.log.Debugf("Pod IP not found in podIPMap for pod %s, skipping pod IP cleanup", podKey)
		return nil
	}

	// Clean up pod IP to pod ID mapping (always do this, even if rule removal fails)
	if podIP != "" {
		filter.DeletePodIPToPodIdEntry(podIP)
		pm.log.Debugf("Cleaned up pod IP to pod ID mapping for pod %s (podIP: %s)", podKey, podIP)
	}

	// Clean up our internal pod IP mapping
	pm.podIPMap.Delete(podKey)
	pm.log.Debugf("Cleaned up internal pod IP mapping for pod %s", podKey)

	// Remove nftables rules
	return pm.removeNFTableRulesInternal(pod)
}

func (pm *proxyManager) removeNFTableRulesInternal(pod types.NamespacedName) error {
	// Check if we have rules for this pod
	rulesInterface, exists := pm.podRules.Load(pod.String())
	if !exists {
		pm.log.Debugf("No nftables rules found for pod %s, nothing to remove", pod.String())
		return nil
	}

	rules := rulesInterface.([]*nftables.Rule)
	pm.log.Infof("Removing %d nftables rules for pod %s", len(rules), pod.String())

	// Delete each rule
	for _, rule := range rules {
		if err := pm.nftConn.DelRule(rule); err != nil {
			pm.log.Warnf("Failed to delete nftables rule for pod %s: %v", pod.String(), err)
		}
	}

	// Flush the deletions
	if err := pm.nftConn.Flush(); err != nil {
		pm.log.Errorf("Failed to flush nftables rule deletions for pod %s: %v", pod.String(), err)
		return fmt.Errorf("failed to flush nftables rule deletions: %w", err)
	}

	// Remove the entry from the map
	pm.podRules.Delete(pod.String())
	pm.log.Infof("Successfully removed %d nftables rules for pod %s", len(rules), pod.String())

	return nil
}

func (pm *proxyManager) checkDNSProxyHealth() error {
	healthEndpoint := fmt.Sprintf("%s:%d", pm.listenerIP.String(), pm.listenerPort+1)
	healthCheckURL := fmt.Sprintf("http://%s/health", healthEndpoint)
	client := &http.Client{
		Timeout: 2 * time.Second, // 2 second timeout for the request
	}

	var attemptNum uint
	err := retry.Do(
		func() error {
			attemptNum++
			pm.log.Debugf("Performing DNS proxy health check (attempt %d/3)...", attemptNum)

			resp, err := client.Get(healthCheckURL)
			if err != nil {
				pm.log.Warnf("DNS proxy health check attempt %d/3 failed: %v", attemptNum, err)
				return fmt.Errorf("DNS proxy health check failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				pm.log.Warnf("DNS proxy health check attempt %d/3 returned status: %d", attemptNum, resp.StatusCode)
				return fmt.Errorf("DNS proxy health check returned non-OK status: %d", resp.StatusCode)
			}

			pm.log.Debugf("DNS proxy health check successful on attempt %d/3 - proxy is ready to serve requests", attemptNum)
			return nil
		},
		retry.Attempts(3),
		retry.Delay(100*time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.LastErrorOnly(true),
	)

	if err != nil {
		pm.log.Errorf("DNS proxy health check failed after 3 attempts: %v", err)
		return fmt.Errorf("DNS proxy health check failed after 3 attempts: %w", err)
	}

	return nil
}

// HealthCheckDNSProxy performs a health check on the DNS proxy
// If the DNS proxy is started, it makes a health check call
// If the DNS proxy is not started, it checks if startup has failed once
// Returns nil (success) if the proxy is healthy
func (pm *proxyManager) HealthCheckDNSProxy() error {
	// If DNS proxy is started, perform health check
	if pm.dnsProxyStarted.Load() {
		return pm.checkDNSProxyHealth()
	}

	// If DNS proxy is not started, check failure count and return err if it failed once
	failedCount := pm.dnsProxyFailed.Load()
	if failedCount >= 1 {
		return fmt.Errorf("DNS proxy has not started and has failed %d times", failedCount)
	}

	// DNS proxy not started - return success
	return nil
}
