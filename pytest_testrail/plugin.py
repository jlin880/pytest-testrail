# -*- coding: UTF-8 -*-
from datetime import datetime
from operator import itemgetter

import jira
import os
import pytest
import re
import sys
import warnings
import logging
from datetime import datetime
from typing import Union, Tuple

# Reference: http://docs.gurock.com/testrail-api2/reference-statuses
TESTRAIL_TEST_STATUS = {
    "passed": 1,
    "blocked": 2,
    "untested": 3,
    "retest": 4,
    "failed": 5,
    "deferred": 6,
    "NA": 7,
    "terraformerror": 8,
}

# Update the mapping for pytest outcomes
PYTEST_TO_TESTRAIL_STATUS = {
    "passed": TESTRAIL_TEST_STATUS["passed"],
    "failed": TESTRAIL_TEST_STATUS["failed"],
    "skipped": TESTRAIL_TEST_STATUS["blocked"],
    "deferred": TESTRAIL_TEST_STATUS["deferred"],
    "NA": TESTRAIL_TEST_STATUS["NA"],
    "terraformerror": TESTRAIL_TEST_STATUS["terraformerror"],
}

DT_FORMAT = "%d-%m-%Y %H:%M:%S"

TESTRAIL_PREFIX = "testrail"
TESTRAIL_DEFECTS_PREFIX = "testrail_defects"
ADD_RESULTS_URL = "add_results_for_cases/{}"
ADD_TESTRUN_URL = "add_run/{}"
CLOSE_TESTRUN_URL = "close_run/{}"
CLOSE_TESTPLAN_URL = "close_plan/{}"
GET_TESTRUN_URL = "get_run/{}"
GET_TESTPLAN_URL = "get_plan/{}"
GET_TESTS_URL = "get_tests/{}"

COMMENT_SIZE_LIMIT = 4000

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class DeprecatedTestDecorator(DeprecationWarning):
    pass


warnings.simplefilter(action="once", category=DeprecatedTestDecorator, lineno=0)


class pytestrail(object):
    """
    An alternative to using the testrail function as a decorator for test cases, since py.test may confuse it as a test
    function since it has the 'test' prefix
    """

    @staticmethod
    def case(*ids):
        """
        Decorator to mark tests with testcase ids.

        ie. @pytestrail.case('C123', 'C12345')

        :return pytest.mark:
        """
        return pytest.mark.testrail(ids=ids)

    @staticmethod
    def defect(*defect_ids):
        """
        Decorator to mark defects with defect ids.

        ie. @pytestrail.defect('PF-513', 'BR-3255')

        :return pytest.mark:
        """
        return pytest.mark.testrail_defects(defect_ids=defect_ids)


def testrail(*ids):
    """
    Decorator to mark tests with testcase ids.

    ie. @testrail('C123', 'C12345')

    :return pytest.mark:
    """
    deprecation_msg = (
        "pytest_testrail: the @testrail decorator is deprecated and will be removed. Please use the "
        "@pytestrail.case decorator instead."
    )
    warnings.warn(deprecation_msg, DeprecatedTestDecorator)
    return pytestrail.case(*ids)


def get_test_outcome(outcome):
    """
    Return numerical value of test outcome.

    :param str outcome: pytest reported test outcome value.
    :returns: int relating to test outcome.
    """
    return PYTEST_TO_TESTRAIL_STATUS[outcome]


def testrun_name():
    """Returns testrun name with timestamp"""
    now = datetime.utcnow()
    return "Automated Run {}".format(now.strftime(DT_FORMAT))


def clean_test_ids(test_ids):
    """
    Clean pytest marker containing testrail testcase ids.

    :param list test_ids: list of test_ids.
    :return list ints: contains list of test_ids as ints.
    """
    return [
        int(re.search("(?P<test_id>[0-9]+$)", test_id).groupdict().get("test_id"))
        for test_id in test_ids
    ]


def clean_test_defects(defect_ids):
    """
    Clean pytest marker containing testrail defects ids.

    :param list defect_ids: list of defect_ids.
    :return list ints: contains list of defect_ids as ints.
    """
    return [
        (re.search("(?P<defect_id>.*)", defect_id).groupdict().get("defect_id"))
        for defect_id in defect_ids
    ]


def get_testrail_keys(items):
    """Return Tuple of Pytest nodes and TestRail ids from pytests markers"""
    testcaseids = []
    for item in items:
        if item.get_closest_marker(TESTRAIL_PREFIX):
            testcaseids.append(
                (
                    item,
                    clean_test_ids(
                        item.get_closest_marker(TESTRAIL_PREFIX).kwargs.get("ids")
                    ),
                )
            )
    return testcaseids


class PyTestRailPlugin(object):
    def __init__(
        self,
        client,
        assign_user_id,
        project_id,
        suite_id,
        include_all,
        cert_check,
        tr_name,
        tr_description="",
        run_id=0,
        plan_id=0,
        version="",
        close_on_complete=False,
        publish_blocked=True,
        skip_missing=False,
        milestone_id=None,
        custom_comment=None,
        jira_owner=None,
        test_dirs=None,
        pr_title=None,
        pr_number=None,
        github_commit_sha=None,
        github_run_id=None,
        controller_build_version=None,
        controller_ami_id=None,
        jira_server=None,
        jira_username=None,
        jira_parent_task_id=None,
    ):
        self.assign_user_id = assign_user_id
        self.cert_check = cert_check
        self.client = client
        self.project_id = project_id
        self.results = []
        self.suite_id = suite_id
        self.include_all = include_all
        self.testrun_name = tr_name
        self.testrun_description = tr_description
        self.testrun_id = run_id
        self.testplan_id = plan_id
        self.version = version
        self.close_on_complete = close_on_complete
        self.publish_blocked = publish_blocked
        self.skip_missing = skip_missing
        self.milestone_id = milestone_id
        self.custom_comment = custom_comment
        self.jira_owner = jira_owner
        self.test_dirs = test_dirs
        self.pr_title = pr_title
        self.pr_number = pr_number
        self.github_commit_sha = github_commit_sha
        self.github_run_id = github_run_id
        self.controller_build_version = controller_build_version
        self.controller_ami_id = controller_ami_id
        self.jira_server = jira_server
        self.jira_username = jira_username
        self.jira_parent_task_id = jira_parent_task_id

    def set_github_env_var(self, var_name, var_value):
        os.environ[var_name] = var_value
        env_file = os.getenv("GITHUB_ENV")
        if env_file:
            with open(env_file, "a") as envfile:
                envfile.write(f"{var_name}={var_value}\n")
        else:
            logging.error("GITHUB_ENV environment variable is not set")

    def get_client(self) -> jira.JIRA:
        user = self.jira_username
        if os.environ.get("JIRA_TOKEN"):
            token = os.environ.get("JIRA_TOKEN")
        if token:
            jira_client = jira.JIRA(self.jira_server, basic_auth=(user, token))
        return jira_client

    def add_comment(self, client: jira.JIRA, issue_id: str, comment: str) -> bool:
        """Add comment to an issue"""
        try:
            issue = client.issue(issue_id)
            client.add_comment(issue, comment)
        except jira.JIRAError as e:
            logging.exception(f"Unable to post comment to {issue_id} {e}")
            return False
        return True

    def check_repeat_comment(
        self, client: jira.JIRA, issue_id: str, msg: str
    ) -> Union[str, None]:
        list_of_comments = client.comments(issue_id)
        for comment in reversed(list_of_comments):
            # reversed ^^ so that we find the last comment made first.
            comment_id: str = comment.id
            assert type(comment_id) == str
            if (
                msg in client.comment(issue_id, comment_id).body
                and client.comment(issue_id, comment_id).author.emailAddress
                == self.jira_username
            ):
                return comment_id
        return None

    def append_repeat_failure(
        self,
        client: jira.JIRA,
        issue_id: str,
        github_commit_sha: str,
        comment_id: str,
        github_run_id: str,
    ) -> bool:
        comment_to_update = client.comment(issue_id, comment_id)
        time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        new_body = f"""
        * Test failure repeated @ {time} on commit {github_commit_sha[0:7]}
        WORKFLOW_URL: https://github.com/AviatrixDev/cloudn/actions/runs/{github_run_id}
        {comment_to_update.body}
        """
        try:
            comment_to_update.update(body=new_body)
        except jira.JIRAError as e:
            logging.exception(
                f"Unable to update comment {comment_id} in issue {issue_id}"
            )
            return False
        return True

    def enrich_msg(
        self,
        msg,
        pr_number: str,
        pr_title: str,
        github_run_id: str,
        github_commit_sha: str,
    ) -> str:
        regex = re.compile(r"^AVX-\d\d\d\d+:? (.*)")
        title = re.search(regex, pr_title).groups()[0]
        new_msg = f"""
        {msg}
        
        PR-{pr_number}
        COMMIT-SHA - {github_commit_sha[0:7]}
        PR Title - {title}
        WORKFLOW_URL - https://github.com/AviatrixDev/cloudn/actions/runs/{github_run_id}
        """
        return new_msg

    def check_if_existing_task_open(
        self, client: jira.JIRA, task_name, username: str
    ) -> Tuple[bool, str]:
        query = f"summary~'\"{task_name}\"' AND resolution = unresolved"
        try:
            res = client.search_issues(query)
            logging.info(f"Jira Search Results: {res}")
            if len(res) > 0:  # There is an existing JIRA
                logging.info(f"Found an existing issue: {res[0].key}")
                out = (True, res[0].key)
            else:
                logging.info("No existing issues found; will have to create one")
                out = (False, "")
        except jira.JIRAError as e:
            logging.error(e)
            out = (False, "")
        return out

    def create_new_task(
        self, client: jira.JIRA, task_name, username, description_text: str
    ) -> bool:
        try:
            issue_id = client.create_issue(
                project={"key": "QE"},
                description=description_text,
                summary=task_name,
                issuetype={"name": "Task"},
                components=[{"name": "e2e"}],
                parent={"key": self.jira_parent_task_id},
            )
            client.assign_issue(issue_id.key, username)
            logging.info(f"Creating new issue for {username} with title {task_name}")
            # logging.info(f"Creating {issue_id.key} for {username} with title {task_name}")
        except jira.JIRAError as e:
            logging.error(f"Could not create a new jira because: {e}")
            return None
        return issue_id

    def generate_workflow_link(self, github_run_id: str) -> str:
        return f"https://github.com/AviatrixDev/cloudn/actions/runs/{github_run_id}"

    def handle_ci_notifications(
        self,
        client: jira.JIRA,
        username: str,
        testname: str,
        outcome: str,
        git_commit_sha: str,
    ) -> None:
        task_name = f"e2e-ci-failure for {testname}"
        exists, issue_id = self.check_if_existing_task_open(client, task_name, username)
        check_mark = "\U00002705"
        cross_mark = "\U0000274C"
        if not exists:  # Create a new task if it doesn't exist
            if outcome == "failure":
                description_text = f"""
                Last failure on ontroller Build Version {self.controller_build_version}:
                [GitHub Actions Workflow]({self.generate_workflow_link(self.github_run_id)})
                AMI ID: {self.controller_ami_id}
                Github Commit SHA: {git_commit_sha}
                Your attention is requested to triage the test suite failure(s).
                If the test is not stable, please remove the pytest marker so this test is not picked up during automated runs.
                """
                summary = f"{task_name}"
                issue_id = self.create_new_task(
                    client, summary, username, description_text
                )
        else:  # Update the existing task
            if outcome == "success":
                comment = f"""
                {check_mark} Test suite {outcome} on Controller Build Version {self.controller_build_version}. Link to workflow:
                [GitHub Actions Workflow]({self.generate_workflow_link(self.github_run_id)})
                AMI ID: {self.controller_ami_id}
                Github Commit SHA: {git_commit_sha}
                """
            else:
                comment = f"""
                {cross_mark} Test suite {outcome} on Controller Build Version {self.controller_build_version}. Link to workflow:
                [GitHub Actions Workflow]({self.generate_workflow_link(self.github_run_id)})
                Your attention is requested to triage the test suite.
                AMI ID: {self.controller_ami_id}
                Github Commit SHA: {git_commit_sha}
                """

            logging.info(
                f"Found an existing issue {issue_id}. Adding another comment to it to capture this {outcome}."
            )
            self.add_comment(client, issue_id, comment)
        return issue_id

    def jira(self) -> str:
        try:
            client = self.get_client()
            if self.pr_title is None:  # No PR associated with this notification
                username = sys.argv[1]
                testname = sys.argv[2]
                outcome = sys.argv[3]  # "success" or "failure"
                regex = re.compile(
                    r"[^a-zA-Z0-9_]+"
                )  # Expecting only letters and numbers
                assert not re.match(regex, username)
                issue_id = self.handle_ci_notifications(
                    client, username, testname, outcome, self.github_commit_sha
                )
            else:  # PR is associated with this notification
                jira_issue = re.findall(r"AVX-[0-9]+", self.pr_title)
                msg = sys.argv[1]
                if len(jira_issue) == 0:
                    logging.error("No JIRA Issue found in the PR title")
                    sys.exit(1)
                else:
                    issue_id = jira_issue[0]

                existing_comment_id = self.check_repeat_comment(client, issue_id, msg)
                if not existing_comment_id:
                    if self.add_comment(
                        client,
                        issue_id,
                        self.enrich_msg(
                            msg,
                            self.pr_number,
                            self.pr_title,
                            self.github_run_id,
                            self.github_commit_sha,
                        ),
                    ):
                        logging.info("Posted comment successfully!")
                else:
                    if self.append_repeat_failure(
                        client,
                        issue_id,
                        self.github_commit_sha,
                        existing_comment_id,
                        self.github_run_id,
                    ):
                        logging.info("Updated comment successfully!")
            self.set_github_env_var("ISSUE_ID", issue_id)
            return issue_id
        except AssertionError:
            logging.error("Checks failed; not creating or updating Jiras!")
            return ""

    # pytest hooks

    def pytest_report_header(self, config, startdir):
        """Add extra-info in header"""
        message = "pytest-testrail: "
        if self.testplan_id:
            message += "existing testplan #{} selected".format(self.testplan_id)
        elif self.testrun_id:
            message += "existing testrun #{} selected".format(self.testrun_id)
        else:
            message += "a new testrun will be created"
        return message

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, session, config, items):
        items_with_tr_keys = get_testrail_keys(items)
        tr_keys = [case_id for item in items_with_tr_keys for case_id in item[1]]

        if self.testplan_id and self.is_testplan_available():
            self.testrun_id = 0
        elif self.testrun_id and self.is_testrun_available():
            self.testplan_id = 0
            if self.skip_missing:
                tests_list = [
                    test.get("case_id") for test in self.get_tests(self.testrun_id)
                ]
                for item, case_id in items_with_tr_keys:
                    if not set(case_id).intersection(set(tests_list)):
                        mark = pytest.mark.skip("Test is not present in testrun.")
                        item.add_marker(mark)
        else:
            if self.testrun_name is None:
                self.testrun_name = testrun_name()

            self.create_test_run(
                self.assign_user_id,
                self.project_id,
                self.suite_id,
                self.include_all,
                self.testrun_name,
                tr_keys,
                self.milestone_id,
                self.testrun_description,
            )

    @pytest.hookimpl(tryfirst=True, hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        """Collect result and associated testcases (TestRail) of an execution"""
        outcome = yield
        rep = outcome.get_result()
        defectids = None
        if "callspec" in dir(item):
            test_parametrize = item.callspec.params
        else:
            test_parametrize = None
        comment = rep.longrepr
        if item.get_closest_marker(TESTRAIL_DEFECTS_PREFIX):
            defectids = item.get_closest_marker(TESTRAIL_DEFECTS_PREFIX).kwargs.get(
                "defect_ids"
            )
        if item.get_closest_marker(TESTRAIL_PREFIX):
            testcaseids = item.get_closest_marker(TESTRAIL_PREFIX).kwargs.get("ids")
            if rep.when in ["setup", "call"] and testcaseids:
                # Check if the test case has already been processed
                if not getattr(item, "testrail_processed", False):
                    # Mark the test case as processed
                    item.testrail_processed = True
                    if defectids:
                        self.add_result(
                            clean_test_ids(testcaseids),
                            get_test_outcome(outcome.get_result().outcome),
                            comment=comment,
                            duration=rep.duration,
                            defects=str(clean_test_defects(defectids))
                            .replace("[", "")
                            .replace("]", "")
                            .replace("'", ""),
                            test_parametrize=test_parametrize,
                        )
                    else:
                        self.add_result(
                            clean_test_ids(testcaseids),
                            get_test_outcome(outcome.get_result().outcome),
                            comment=comment,
                            duration=rep.duration,
                            test_parametrize=test_parametrize,
                        )

    def pytest_sessionfinish(self, session, exitstatus):
        """Publish results in TestRail"""
        logger.info("[{}] Start publishing".format(TESTRAIL_PREFIX))
        self.jira()
        error = None
        if not self.results:
            logger.error("[{}] No test results to publish".format(TESTRAIL_PREFIX))
            raise Exception("No test results to publish in TestRail")

        tests_list = [str(result["case_id"]) for result in self.results]
        logger.info(
            "[{}] Testcases to publish: {}".format(
                TESTRAIL_PREFIX, ", ".join(tests_list)
            )
        )
        if self.testrun_id:
            error = self.publish_results_for_run(
                self.testrun_id, github_run_id=self.github_run_id
            )
        elif self.testplan_id:
            testruns = self.get_available_testruns(
                self.testplan_id, github_run_id=self.github_run_id
            )
            logger.info(
                "[{}] Testruns to update: {}".format(
                    TESTRAIL_PREFIX, ", ".join(map(str, testruns))
                )
            )
            for testrun_id in testruns:
                error = self.publish_results_for_run(
                    testrun_id, github_run_id=self.github_run_id
                )
        else:
            logger.info("[{}] No data published".format(TESTRAIL_PREFIX))

        if self.close_on_complete and self.testrun_id:
            self.close_test_run(self.testrun_id)
        elif self.close_on_complete and self.testplan_id:
            self.close_test_plan(self.testplan_id)
        if error:
            logger.error(
                "[{}] Exception occurred during publishing: {}".format(
                    TESTRAIL_PREFIX, str(error)
                )
            )
            raise Exception(
                "Error occurred during publishing in TestRail: {}".format(str(error))
            )
        else:
            logger.info("[{}] End publishing".format(TESTRAIL_PREFIX))

    def publish_results_for_run(self, testrun_id, github_run_id=None):
        """Publish results for a specific test run"""
        error = self.add_results(testrun_id, github_run_id)
        if error:
            terraform_errors = self.extract_terraform_errors(error)
            if terraform_errors:
                for test_id, terraform_error in terraform_errors.items():
                    self.add_terraform_error_results(
                        testrun_id, test_id, terraform_error
                    )
                print(
                    "[{}] Terraform errors successfully reported for testrun {}".format(
                        TESTRAIL_PREFIX, testrun_id
                    )
                )
            else:
                print(
                    "[{}] Other errors occurred, reporting them for testrun {}".format(
                        TESTRAIL_PREFIX, testrun_id
                    )
                )
                error_message_parts = error.split(")")
                # TODO: Not sure how to support test code with only one case [{'case_id': 38432499366, 'status_id': 1, 'comment': 'None', 'duration': 287.6693093829963, 'defects': None, 'test_parametrize': None}]
                invalid_test_ids = []
                for part in error_message_parts:
                    if "case" in part:
                        split_part = part.split("case ")
                        if len(split_part) > 1:
                            invalid_test_ids.append(split_part[1].split(" ")[0])

                valid_results = [
                    result
                    for result in self.results
                    if result["case_id"] not in invalid_test_ids
                ]
                for invalid_test_id in invalid_test_ids:
                    self.add_error_results(
                        testrun_id, [invalid_test_id], error, github_run_id
                    )
            return error
        else:
            print(
                "[{}] Test results successfully published for testrun {}".format(
                    TESTRAIL_PREFIX, testrun_id
                )
            )

    def extract_terraform_errors(self, error_message):
        """Extract Terraform errors from the error message"""
        terraform_errors = {}
        for match in re.finditer(
            r"case (\d+).*?TerraformException: (.+?)\\n", error_message
        ):
            test_id = match.group(1)
            error = match.group(2)
            terraform_errors[test_id] = error
        return terraform_errors

    def add_terraform_error_results(self, testrun_id, test_id, terraform_error):
        """Add results for Terraform errors"""
        status_id = "8"  # Update status_id for Terraform errors
        comment = "Terraform Exception: {}".format(
            terraform_error
        )  # Modify comment to reflect Terraform error
        self.client.send_post(
            "add_result_for_case/{}/{}".format(testrun_id, test_id),
            {"status_id": status_id, "comment": comment},
        )

    # plugin

    def add_result(
        self,
        test_ids,
        status,
        comment="",
        defects=None,
        duration=0,
        test_parametrize=None,
    ):
        """
        Add a new result to results dict to be submitted at the end.

        :param list test_parametrize: Add test parametrize to test result
        :param defects: Add defects to test result
        :param list test_ids: list of test_ids.
        :param int status: status code of test (pass or fail).
        :param comment: None or a failure representation.
        :param duration: Time it took to run just the test.
        """
        for test_id in test_ids:
            # Convert comment to string if it's not already
            if not isinstance(comment, str):
                comment = str(comment)

            # Update status code from 5 to 6 for Terraform errors
            if status == 5 and "TerraformException" in comment:
                status = 8

            data = {
                "case_id": test_id,
                "status_id": status,
                "comment": comment,
                "duration": duration,
                "defects": defects,
                "test_parametrize": test_parametrize,
            }
            self.results.append(data)
            logger.info(
                "Added result for case {}: status={}, comment={}, defects={}, duration={}, test_parametrize={}".format(
                    test_id, status, comment, defects, duration, test_parametrize
                )
            )

    def add_error_results(self, testrun_id, invalid_test_ids, error, github_run_id):
        """
        Add error results for test cases excluding the invalid test case IDs.

        :param testrun_id: ID of the test run.
        :param invalid_test_ids: List of invalid test case IDs.
        :param error: Error message.
        """
        # Log the error message and invalid test case IDs
        logger.error(
            '[{}] Info: Testcases not published for the following reason: "{}"'.format(
                TESTRAIL_PREFIX, error
            )
        )
        logger.error(
            "[{}] Invalid test case IDs: {}".format(TESTRAIL_PREFIX, invalid_test_ids)
        )

        # Remove the leading "C" character from invalid test case IDs if the first character is "C"
        invalid_test_ids = [
            id[1:] if id.startswith("C") else id for id in invalid_test_ids
        ]
        valid_results = [
            result
            for result in self.results
            if result["case_id"] not in invalid_test_ids
        ]
        data = {"results": []}
        for result in valid_results:
            entry = {
                "case_id": result["case_id"],
                "status_id": TESTRAIL_TEST_STATUS["failed"],
                "comment": error,
                "defects": "",
            }
            # Directly call the TestRail API to add the result to the test run
            response = self.client.send_post(
                ADD_RESULTS_URL.format(testrun_id),
                {"results": [entry]},
                cert_check=self.cert_check,
            )

            logger.info("Response received for error result: {}".format(response))

            error_response = self.client.get_error(response)

            if error_response:
                logger.error(
                    '[{}] Error adding result for case {}: "{}"'.format(
                        TESTRAIL_PREFIX, result["case_id"], error_response
                    )
                )

    def add_results(self, testrun_id, github_run_id=None):
        """
        Add results one by one to improve error handling.

        :param testrun_id: ID of the test run to feed.
        :param github_run_id: GitHub Actions run ID.
        """
        # Unicode converter for compatibility with Python 2 and 3
        try:
            converter = unicode
        except NameError:
            converter = lambda s, c: str(bytes(s, "utf-8"), c)

        # Results are sorted by 'case_id'
        self.results.sort(key=itemgetter("case_id"))

        # Manage case of "blocked" test cases
        if not self.publish_blocked:
            print(
                '[{}] Option "Don\'t publish blocked test cases" activated'.format(
                    TESTRAIL_PREFIX
                )
            )
            blocked_tests_list = [
                test.get("case_id")
                for test in self.get_tests(testrun_id)
                if test.get("status_id") == TESTRAIL_TEST_STATUS["blocked"]
            ]
            print(
                "[{}] Blocked test cases excluded: {}".format(
                    TESTRAIL_PREFIX, ", ".join(str(elt) for elt in blocked_tests_list)
                )
            )
            self.results = [
                result
                for result in self.results
                if result.get("case_id") not in blocked_tests_list
            ]

        # Prompt enabling include all test cases from test suite when creating test run
        if self.include_all:
            print(
                '[{}] Option "Include all test cases from test suite for test run" activated'.format(
                    TESTRAIL_PREFIX
                )
            )

        # Publish results
        data = {"results": []}
        for result in self.results:
            entry = {
                "status_id": result["status_id"],
                "case_id": result["case_id"],
                "defects": result["defects"],
            }
            if self.version:
                entry["version"] = self.version
            comment = result.get("comment", "")
            test_parametrize = result.get("test_parametrize", "")
            entry["comment"] = ""
            if test_parametrize:
                entry["comment"] += "# Test parametrize: #\n"
                entry["comment"] += str(test_parametrize) + "\n\n"
            if comment:
                if self.custom_comment:
                    entry["comment"] += self.custom_comment + "\n"
                    # Indent text to avoid string formatting by TestRail. Limit size of comment.
                    entry["comment"] += "# Pytest result: #\n"
                    entry["comment"] += (
                        "Log truncated\n...\n"
                        if len(str(comment)) > COMMENT_SIZE_LIMIT
                        else ""
                    )
                    entry["comment"] += "    " + converter(str(comment), "utf-8")[
                        -COMMENT_SIZE_LIMIT:
                    ].replace(
                        "\n", "\n    "
                    )  # noqa
                else:
                    # Indent text to avoid string formatting by TestRail. Limit size of comment.
                    entry["comment"] += "# Pytest result: #\n"
                    entry["comment"] += (
                        "Log truncated\n...\n"
                        if len(str(comment)) > COMMENT_SIZE_LIMIT
                        else ""
                    )
                    entry["comment"] += "    " + converter(str(comment), "utf-8")[
                        -COMMENT_SIZE_LIMIT:
                    ].replace(
                        "\n", "\n    "
                    )  # noqa
            elif comment == "":
                entry["comment"] = self.custom_comment

            if github_run_id:
                workflow_url = (
                    f"https://github.com/test/cloudn/actions/runs/{github_run_id}"
                )
                entry["comment"] += f"\nGitHub Actions run URL: {workflow_url}"

            duration = result.get("duration")
            if duration:
                duration = (
                    1 if (duration < 1) else int(round(duration))
                )  # TestRail API doesn't manage milliseconds
                entry["elapsed"] = str(duration) + "s"
            data["results"].append(entry)

        response = self.client.send_post(
            ADD_RESULTS_URL.format(testrun_id), data, cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if isinstance(response, str) and "error" in response:
            logger.error(
                "Error in sending results to TestRail. Response: {}".format(response)
            )
        if isinstance(response, list):
            for resp in response:
                comment = resp.get("comment", "")
                if "TerraformException" in comment:
                    status_id = resp.get("status_id")
                    self.add_terraform_error_results(testrun_id, status_id, comment)
        error = self.client.get_error(response)
        if error:
            return error

    def create_test_run(
        self,
        assign_user_id,
        project_id,
        suite_id,
        include_all,
        testrun_name,
        tr_keys,
        milestone_id,
        description="",
    ):
        """
        Create testrun with ids collected from markers.

        :param tr_keys: collected testrail ids.
        """
        data = {
            "suite_id": suite_id,
            "name": testrun_name,
            "description": description,
            "assignedto_id": assign_user_id,
            "include_all": include_all,
            "case_ids": tr_keys,
            "milestone_id": milestone_id,
        }

        response = self.client.send_post(
            ADD_TESTRUN_URL.format(project_id), data, cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print('[{}] Failed to create testrun: "{}"'.format(TESTRAIL_PREFIX, error))
        else:
            self.testrun_id = response["id"]
            print(
                '[{}] New testrun created with name "{}" and ID={}'.format(
                    TESTRAIL_PREFIX, testrun_name, self.testrun_id
                )
            )

    def close_test_run(self, testrun_id):
        """
        Closes testrun.

        """
        response = self.client.send_post(
            CLOSE_TESTRUN_URL.format(testrun_id), data={}, cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print('[{}] Failed to close test run: "{}"'.format(TESTRAIL_PREFIX, error))
        else:
            print(
                "[{}] Test run with ID={} was closed".format(
                    TESTRAIL_PREFIX, self.testrun_id
                )
            )

    def close_test_plan(self, testplan_id):
        """
        Closes testrun.

        """
        response = self.client.send_post(
            CLOSE_TESTPLAN_URL.format(testplan_id), data={}, cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print('[{}] Failed to close test plan: "{}"'.format(TESTRAIL_PREFIX, error))
        else:
            print(
                "[{}] Test plan with ID={} was closed".format(
                    TESTRAIL_PREFIX, self.testplan_id
                )
            )

    def is_testrun_available(self):
        """
        Ask if testrun is available in TestRail.

        :return: True if testrun exists AND is open
        """
        response = self.client.send_get(
            GET_TESTRUN_URL.format(self.testrun_id), cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print(
                '[{}] Failed to retrieve testrun: "{}"'.format(TESTRAIL_PREFIX, error)
            )
            return False

        return response["is_completed"] is False

    def is_testplan_available(self):
        """
        Ask if testplan is available in TestRail.

        :return: True if testplan exists AND is open
        """
        response = self.client.send_get(
            GET_TESTPLAN_URL.format(self.testplan_id), cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print(
                '[{}] Failed to retrieve testplan: "{}"'.format(TESTRAIL_PREFIX, error)
            )
            return False

        return response["is_completed"] is False

    def get_available_testruns(self, plan_id):
        """
        :return: a list of available testruns associated to a testplan in TestRail.

        """
        testruns_list = []
        response = self.client.send_get(
            GET_TESTPLAN_URL.format(plan_id), cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print(
                '[{}] Failed to retrieve testplan: "{}"'.format(TESTRAIL_PREFIX, error)
            )
        else:
            for entry in response["entries"]:
                for run in entry["runs"]:
                    if not run["is_completed"]:
                        testruns_list.append(run["id"])
        return testruns_list

    def get_tests(self, run_id):
        """
        :return: the list of tests containing in a testrun.

        """
        response = self.client.send_get(
            GET_TESTS_URL.format(run_id), cert_check=self.cert_check
        )
        error = self.client.get_error(response)
        if error:
            print('[{}] Failed to get tests: "{}"'.format(TESTRAIL_PREFIX, error))
            return None
        return response
