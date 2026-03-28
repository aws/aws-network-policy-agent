## Integration Test scripts

This package contains shell scripts and libraries used for running e2e integration tests.

### Shell scripts

`run-test.sh` - Can run various integration test suites against the current revision in the invoking directory. This script is primarily used for running tests github actions

`run-cyclonus-tests.sh` - Runs policy-assistant tests (successor to cyclonus) against an existing cluster and validates the output

`update-node-agent-image.sh` - Update the node agent image in the cluster to the image specified in `AWS_EKS_NODEAGENT` parameter using helm chart.

#### Tests
The following tests are valid to run using `run-test.sh` script, and setting the respective environment variable to true will run them:
1. Conformance Tests - `RUN_CONFORMANCE_TESTS`
2. Performance Tests - `RUN_PERFORMANCE_TESTS`


#### Conformance tests
This runs the upstream policy-assistant test suite (successor to cyclonus from kubernetes-sigs/network-policy-api) for comprehensive network policy testing. Policy-assistant includes additional tests beyond the original cyclonus suite, including AdminNetworkPolicy tests.


#### Performance tests
This runs the upstream policy-assistant tests and collects the memory metrics during the run
