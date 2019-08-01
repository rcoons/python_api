import unittest
import os
import sys
from report.BeautifulReport import BeautifulReport
dir_target = sys.argv[1]
test_target = sys.argv[2]

case_path = os.path.join(os.getcwd(), dir_target)
print(case_path)


def CreatSuite():
    suite = unittest.TestSuite()
    discover = unittest.defaultTestLoader.discover(case_path, pattern=test_target, top_level_dir=None)
    for test_case in discover:
        suite.addTests(test_case)
    return suite


if __name__ == "__main__":
    prj_name = sys.argv[3]
    all_test = CreatSuite()
    result = BeautifulReport(all_test)
    result.report(filename='TestReport', description=prj_name, log_path='.')
