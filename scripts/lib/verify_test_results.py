import re
import sys
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file-name",default="", dest="file_name",help="Cyclonus results log file")
    parser.add_argument("-ip", "--ip-family",default="IPv4", dest="ip_family",help="IP Family of the cluster")
    args = parser.parse_args()
    verify_results(args.file_name,args.ip_family)

def verify_results(file_name,ip_family):

    # Cyclonus runs 112 test cases in total where each case has a number sub tests. AWS NP doesn't support all these sub-tests
    # expected_results maintains a mapping of the test number and the number of sub-tests that are expected to pass for v4/v6 clusters
    # For the test numbers not included in this map, it is expected that all the sub-tests should be passing
    if ip_family == "IPv6":
        expected_results={ 2:80, 3:80, 8:80, 12:64, 23:80, 25:80, 26:80, 28:80, 29:80, 31:50, 32:64, 98:80, 102:72, 104:72, 106:72, 108:72, 111:80, 112:80 }
    else:
        expected_results={ 2:80, 3:80, 8:80, 12:80, 23:80, 25:80, 26:80, 28:80, 29:80, 31:50, 32:64, 98:80, 111:80, 112:80 }

    start="starting test case"
    wrong="wrong"
    ignored="ignored"
    correct="correct"
    delimiter=':|\ |,|\\n'
    test_number=0
    is_test_run_failed=False
    step=0

    # Open the log file in read-only mode
    with open(file_name, 'r') as filedata:
        for line in filedata:
            # Checking if the keywords are found in the line
            is_test_case_failed=False
            if all(key in line for key in [wrong,ignored,correct]):
                step+=1
                words=re.split(delimiter, line)
                count_wrong=int(words[words.index(wrong)-1])
                count_correct=int(words[words.index(correct)-1])
                count_ignored=int(words[words.index(ignored)-1])

                # Expected correct count by default
                expected_correct=count_wrong+count_correct+count_ignored

                # Check if test results are expected
                if test_number in expected_results.keys():

                    if isinstance(expected_results[test_number], dict):
                        expected_correct=expected_results[test_number][step]
                    else:
                        expected_correct=expected_results[test_number]
                    # In v6 cluster, test #31 depends on which nodes the pod runs on, so we use here ( < ) instead of ( != )
                    if count_correct < expected_correct:
                        is_test_case_failed=True
                elif count_wrong > 0:
                    is_test_case_failed=True

                if is_test_case_failed:
                    # Mark the entire test run as fail since atleast one test deviated from the expected results
                    is_test_run_failed=True
                    print("Test Number:{test_number} | step:{step} | Failed -> Correct:{count_correct} Expected:{expected_correct}".format(
                        test_number=test_number,
                        step=step,
                        count_correct=count_correct,
                        expected_correct=expected_correct
                    ))
                else:
                    print("Test Number:{test_number} | step:{step} | Passed -> Correct:{count_correct} Expected:{expected_correct}".format(
                        test_number=test_number,
                        step=step,
                        count_correct=count_correct,
                        expected_correct=expected_correct
                    ))

            # This denotes the start of test
            elif start in line:
                step=0
                test_number=int(line.split("#")[1])
                is_test_case_failed=False
            else:
                continue

    # Fail test if either flag is true or all 112 tests did not get executed
    if is_test_run_failed or test_number != 112:
        print("Test Run Failed. Check failures")
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
