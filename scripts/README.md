## Integration Test scripts

This package contains shell scripts and libraries used for running e2e integration tests.

### run-test.sh

`run-test.sh` can run various integration test suites against the current revision in the invoking directory. 
`run-cyclonus-tests.sh` Runs cyclonus tests against an existing cluster and validates the output

#### Tests
The following tests are valid to run using `run-test.sh` script, and setting the respective environment variable to true will run them:
1. Conformance Tests - `RUN_CONFORMANCE_TESTS`
2. Performance Tests - `RUN_PERFORMANCE_TESTS`


#### Conformance tests
This runs the upstream cyclonus test suite for testing network policy


#### Performance tests
This for now runs the upstream cyclonus tests and only collects the memory metrics during the run
