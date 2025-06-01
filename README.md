# aws-network-policy-agent
Amazon EKS Network Policy Agent is a daemonset that is responsible for enforcing configured network policies on the cluster. Network policy support is a feature of the [Amazon VPC CNI](https://github.com/aws/amazon-vpc-cni-k8s). 

[Network Policy Controller](https://github.com/aws/amazon-network-policy-controller-k8s/) resolves the configured network policies and publishes the resolved endpoints via Custom CRD (`PolicyEndpoints`) resource. Network Policy agent derives the endpoints from PolicyEndpoint resources and enforces them via eBPF probes attached to pod's host Veth interface.

Starting with Amazon VPC CNI v1.14.0, Network Policy agent will be automatically installed. Review the instructions in the [EKS User Guide](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html).

## Getting Started
You’ll need a Kubernetes cluster version 1.25+ to run against. You can use [KIND](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.

**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

## Prerequisites 
 - You need to install [Network Policy Controller](https://github.com/aws/amazon-network-policy-controller-k8s/) in your cluster before you can enable the feature in VPC CNI. When you create a new Amazon EKS cluster, the controller will be automatically installed in EKS control plane.
 - Network Policy Agent expects the BPF FS (`/sys/fs/bpf`) to be mounted. If you rely on EKS AMIs, all v1.27+ EKS AMIs will mount BPF FS by default. For v1.25 and v1.26 clusters, EKS AMIs above version https://github.com/awslabs/amazon-eks-ami/releases/tag/v20230703 will mount the BPF FS by default.
 - PolicyEndpoint CRD needs to be installed in the cluster. Installing Network Policy Controller will automatically install the CRD.

## Setup
Download the latest version of the [yaml](https://github.com/aws/amazon-vpc-cni-k8s/tree/release-1.14/config) and apply it to the cluster.

Please refer to [EKS User Guide](https://docs.aws.amazon.com/eks/latest/userguide/cni-network-policy.html) on how to enable the feature.

### Network Policy Agent Configuration flags
---

#### `enable-network-policy`

Type: Boolean

Default: false

Set this flag to `true` to enable the Network Policy feature support.

#### `enable-policy-event-logs`

Type: Boolean

Default: false

Set this flag to `true` to enable the collection & logging of policy decision logs.

> Notice: Enabling this feature requires one CPU core per node.

#### `enable-cloudwatch-logs`

Type: Boolean

Default: false

Network Policy Agent provides an option to stream policy decision logs to Cloudwatch. For EKS clusters, the policy logs will be located under `/aws/eks/<cluster-name>/cluster/` and for self-managed K8S clusters, the logs will be placed under `/aws/k8s-cluster/cluster/`. By default, Network Policy Agent will log policy decision information for individual flows to a file on the local node (`/var/run/aws-routed-eni/network-policy-agent.log`).

This feature requires to also enable the `enable-policy-event-logs` flag.

This feature requires you to provide relevant Cloudwatch permissions to `aws-node` pod via the below policy.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
```

#### `enable-ipv6`

Type: Boolean

Default: false

Network Policy agent can operate in either IPv4 or IPv6 mode. Setting this flag to `true` in the manifest will configure it in IPv6 mode.

**Note:** VPC CNI by default creates an egress only IPv4 interface for IPv6 pods and this network interface will not be secured by the Network policy feature. Network policies will only be enforced on the Pod's primary interface (i.e.,) `eth0`. If you want to block the egress IPv4 access, please disable the interface creation via [ENABLE_V4_EGRESS](https://github.com/aws/amazon-vpc-cni-k8s#enable_v4_egress-v1151) flag in VPC CNI. 

#### `log-level`

Type: String

Default: debug

Sets the logging verbosity for the Network Policy Agent. Valid options are: debug, info, warn, error.
DENY flow logs are always logged, regardless of the log level.
ACCEPT flow logs are logged only at debug level, and only if --enable-policy-event-logs is set to true

#### `conntrack-cache-cleanup-period` (from v1.0.7+)

Type: Integer

Default: 300

Network Policy agent maintains a local conntrack cache. This configuration (in seconds) will determine how fast the local conntrack cache should be cleaned up from stale/expired entries. Based on the time interval set, network policy agent checks every entry in the local conntrack cache with kernel conntrack table and determine if the entry has to be deleted.

#### `conntrack-cache-table-size` (from v1.1.3+)

Type: Integer

Default: 1024 * 256

Network Policy agent maintains a local conntrack cache. Ideally this should be of the same size as kernel conntrack table. Note, this should be configured on new nodes before enabling network policy or if network policy is already enabled the change in configuration would need a reload of the nodes. Dynamic update of conntrack map size would lead to traffic disruption and isn't supported. The value supported is between 32K and 1024K.

**Note**: To check the maximum conntrack table size in your linux worker node, use the following command:

```console
$ cat /proc/sys/net/netfilter/nf_conntrack_max
262144
```

## Network Policy Agent CLI
The Amazon VPC CNI plugin for Kubernetes installs eBPF SDK collection of tools on the nodes. You can use the eBPF SDK tools to identify issues with network policies. For example, the following command lists the programs that are running on the node.

**Note:**: To run this CLI, you can use any method to connect to the node. CLI binary is located at `/opt/cni/bin`.

**Usage**:

```
./aws-eks-na-cli ebpf -h
Dump all ebpf related data

Usage:
  aws-eks-na-cli ebpf [flags]
  aws-eks-na-cli ebpf [command]

Aliases:
  ebpf, ebpf

Available Commands:
  dump-maps       Dump all ebpf maps related data
  loaded-ebpfdata Dump all ebpf related data
  maps            Dump all ebpf maps related data
  progs           Dump all ebpf program related data
```

- Load all eBPF programs managed by Network Policy Agent

```
   ./aws-eks-na-cli ebpf progs

Example:

./aws-eks-na-cli ebpf progs
Programs currently loaded : 
Type : 26 ID : 6 Associated maps count : 1
========================================================================================
Type : 26 ID : 8 Associated maps count : 1
========================================================================================
Type : 3 ID : 57 Associated maps count : 3
========================================================================================
```

- Load all eBPF maps managed by Network Policy Agent
  
```
   ./aws-eks-na-cli ebpf maps

Example:

./aws-eks-na-cli ebpf maps
Maps currently loaded : 
Type : 2 ID : 45
Keysize 4 Valuesize 98 MaxEntries 1
========================================================================================
Type : 9 ID : 201
Keysize 16 Valuesize 1 MaxEntries 65536
========================================================================================
```

- Print Map contents by ID
  
```
   ./aws-eks-na-cli ebpf dump-maps <Map-ID>
  
Example:

./aws-eks-na-cli ebpf dump-maps 40
Key : IP/Prefixlen - 192.168.61.236/32 
Value : 
Protocol -  254
StartPort -  0
Endport -  0
*******************************
Key : IP/Prefixlen - 0.0.0.0/0 
Value : 
Protocol -  254
StartPort -  0
Endport -  0
*******************************
```

- Load all eBPF related programs and maps managed by Network Policy Agent
  
```
   ./aws-eks-na-cli ebpf loaded-ebpfdata

Example:
./aws-eks-na-cli ebpf loaded-ebpfdata
pinPathName: busybox-deployment-77948c5466-default_handle_egress
PinPath:  /sys/fs/bpf/globals/aws/programs/busybox-deployment-77948c5466-default_handle_egress
Pod Identifier : busybox-deployment-77948c5466-default  Direction : egress 
Prog FD:  9
Associated Maps -> 
Map Name:  
Map ID:  224
Map Name:  egress_map
Map ID:  225
========================================================================================
pinPathName:  busybox-deployment-77948c5466-default_handle_ingress
PinPath:  /sys/fs/bpf/globals/aws/programs/busybox-deployment-77948c5466-default_handle_ingress
Pod Identifier : busybox-deployment-77948c5466-default  Direction : ingress 
Prog FD:  13
Associated Maps -> 
Map Name:  
Map ID:  224
Map Name:  ingress_map
Map ID:  226
========================================================================================
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for more information.

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/),
which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Modifying the API definitions
If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Security Disclosures 

If you think you’ve found a potential security issue, please do not post it in the Issues. Instead, please follow the
instructions [here](https://aws.amazon.com/security/vulnerability-reporting/) or [email AWS security directly](mailto:aws-security@amazon.com).