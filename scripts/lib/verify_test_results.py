import re
import sys
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file-name",default="", dest="file_name",help="Cyclonus results log file")
    parser.add_argument("-ip", "--ip-family",default="IPv4", dest="ip_family",help="IP Family of the cluster")
    args = parser.parse_args()

    # Cyclonus runs 112 test cases in total with each having some steps. Each step runs 81 probes in total across TCP, UDP and SCTP protocol
    # AWS Network Policy doesn't support all these combinations. We maintain a mapping of the test number and the number of
    # probes that are expected to pass on each testcase+step combination for IPv4 and IPv6 cluster.
    # For the test numbers not included in this map, it is expected that all the probes should be passing
    if args.ip_family.lower() == "ipv6":
        expected_results={ 2:{'Step 1': 80}, 3:{'Step 1': 80}, 8:{'Step 1': 80}, 12:{'Step 1': 64}, 23:{'Step 1': 80}, 25:{'Step 1': 80}, 26:{'Step 1': 80}, 28:{'Step 1': 80}, 29:{'Step 1': 80}, 31:{'Step 1': 50}, 32:{'Step 1': 64}, 98:{'Step 1': 79}, 102:{'Step 1': 71}, 104:{'Step 1': 71}, 106:{'Step 1': 71}, 108:{'Step 1': 71}, 111:{'Step 1': 79}, 112:{'Step 1': 80} }
    else:
        expected_results={ 2:{'Step 1': 80}, 3:{'Step 1': 80}, 8:{'Step 1': 80}, 12:{'Step 1': 80}, 23:{'Step 1': 80}, 25:{'Step 1': 80}, 26:{'Step 1': 80}, 28:{'Step 1': 80}, 29:{'Step 1': 80}, 31:{'Step 1': 50}, 32:{'Step 1': 64}, 98:{'Step 1': 80}, 111:{'Step 1': 80}, 112:{'Step 1': 80}}

    results = capture_results(args.file_name)
    verify_results(results,expected_results)

def capture_results(file_name):
    results = {}
    rowbreak = False
    start_capture = False
    test_number = 0
    with open(file_name, 'r') as filedata:
        for data in filedata:
            if start_capture:
                if len(data.strip()) == 0:
                    break
                elif data.startswith("+---"):
                    rowbreak = True
                else:
                    keys = [x.strip() for x in data.split('|')]
                    if keys[1] == "TEST":
                        continue
                    elif rowbreak:
                        if keys[2] in ["passed", "failed"]:
                            test_number = int(keys[1].split(":")[0])
                            results[test_number] = {}
                        else:
                            # Capture all retries for a testcase+step combination to verify
                            step = keys[3].split(",")[0]
                            if step not in results[test_number]:
                                results[test_number][step] = []
                            results[test_number][step].append([int(keys[4]),int(keys[5]),int(keys[6])])
                        rowbreak = False
                    else:
                        continue
            elif "SummaryTable:" in data:
                start_capture = True
            else:
                continue
    return results


def verify_results(results,expected_results):

    is_test_run_failed = False
    for test_number in results.keys():
        for step in results[test_number].keys():
            is_test_case_failed = True
            expected_correct = 0

            # Verifiying result from each retry for testcase+step
            for try_result in results[test_number][step]:
                count_failed, count_correct, count_ignored = try_result
                # Expected correct count by default for a testcase+step
                expected_correct = count_failed + count_correct + count_ignored

                if test_number in expected_results.keys():
                    if step in expected_results[test_number]:
                        expected_correct = expected_results[test_number][step]

                # Check if the number of probes passed in testcase+step are as expected
                if count_correct >= expected_correct:
                    print("Test Number:{test_number} | {step} | Passed -> Correct:{count_correct} Expected:{expected_correct}".format(
                        test_number=test_number,step=step,
                        count_correct=try_result[1],expected_correct=expected_correct
                    ))
                    is_test_case_failed = False
                    break

            if is_test_case_failed:
                print("Test Number:{test_number} | {step} | Failed -> Try results: {probes} Expected:{expected_correct}".format(
                        test_number=test_number,step=step,
                        probes=results[test_number][step],expected_correct=expected_correct
                ))
                # Mark the entire test run as fail since atleast one test deviated from the expected results
                is_test_run_failed=True

    if is_test_run_failed or len(results) !=112:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
