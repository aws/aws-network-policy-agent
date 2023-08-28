## Integration Test scripts

This package contains shell scripts and libraries used for running e2e integration tests.

### run-test.sh

`run-test.sh` can run various integration test suites against the current revision in the invoking directory. 

#### Tests
The following tests are valid to run, and setting the respective environment variable to true will run them:
1. Conformance Tests - `RUN_CONFORMANCE_TESTS`
2. Performance Tests - `RUN_PERFORMANCE_TESTS`


#### Conformance tests
This runs the upstream cyclonus test suite for testing network policy


#### Performance tests
This for now runs the upstream cyclonus tests and only collects the memory metrics during the run
