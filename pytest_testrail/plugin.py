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
RESULTS_DIR = "/home/ubuntu"
RESULTS_FILE_PATH = os.path.join(RESULTS_DIR, "test_results.txt")

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
        jira_token=None,
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
        self.jira_token = jira_token
        self.issue_id = ""

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
        token = self.jira_token
        jira_client = None
        if token:
            jira_client = jira.JIRA(self.jira_server, basic_auth=(user, token))
        else:
            logging.error(
                "JIRA_TOKEN is not set, unable to create or update jira ticket"
            )
        return jira_client

    def add_context(self, client: jira.JIRA, issue_id: str, context: str) -> bool:
        """Add context to an issue"""
        try:
            issue = client.issue(self.issue_id)
            client.add_comment(issue, context)
        except jira.JIRAError as e:
            logging.exception(f"Unable to post context to {self.issue_id} {e}")
            return False
        return True

    def check_repeat_context(
        self, client: jira.JIRA, issue_id: str, msg: str
    ) -> Union[str, None]:
        list_of_contexts = client.contexts(self.issue_id)
        for context in reversed(list_of_contexts):
            # reversed ^^ so that we find the last context made first.
            context_id: str = context.id
            assert type(context_id) == str
            if (
                msg in client.context(self.issue_id, context_id).body
                and client.context(self.issue_id, context_id).author.emailAddress
                == self.jira_username
            ):
                return context_id
        return None

    def append_repeat_failure(
        self,
        client: jira.JIRA,
        issue_id: str,
        github_commit_sha: str,
        context_id: str,
        github_run_id: str,
    ) -> bool:
        context_to_update = client.context(self.issue_id, context_id)
        time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        new_body = f"""
        * Test failure repeated @ {time} on commit {github_commit_sha[0:7]}
        WORKFLOW_URL: https://github.com/AviatrixDev/cloudn/actions/runs/{github_run_id}
        {context_to_update.body}
        """
        try:
            context_to_update.update(body=new_body)
        except jira.JIRAError as e:
            logging.exception(
                f"Unable to update context {context_id} in issue {self.issue_id}"
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
        self, client: jira.JIRA, task_name
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
            self.issue_id = client.create_issue(
                project={"key": "QE"},
                description=description_text,
                summary=task_name,
                issuetype={"name": "Task"},
                components=[{"name": "e2e"}],
                parent={"key": self.jira_parent_task_id},
            )
            client.assign_issue(self.issue_id.key, username)
            logging.info(f"Creating new issue for {username} with title {task_name}")
            # logging.info(f"Creating {self.issue_id.key} for {username} with title {task_name}")
        except jira.JIRAError as e:
            logging.error(f"Could not create a new jira because: {e}")
            return None
        return self.issue_id

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
        exists, self.issue_id = self.check_if_existing_task_open(client, task_name)
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
                self.issue_id = self.create_new_task(
                    client, summary, username, description_text
                )
        return self.issue_id

    def jira(self, outcome: str) -> str:
        try:
            client = self.get_client()
            username = self.jira_owner
            testname = self.test_dirs
            regex = re.compile(r"[^a-zA-Z0-9_]+")  # Expecting only letters and numbers
            logger.info("username" + username)
            logger.info("testname" + testname)
            self.issue_id = self.handle_ci_notifications(
                client, username, testname, outcome, self.github_commit_sha
            )

            self.set_github_env_var("self.issue_id", self.issue_id)
            return self.issue_id
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

            if self.testrun_id is None:
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
        outcome = "success"
        for result in self.results:
            if result["status_id"] == 5:
                outcome = "failure"
                break
        logger.info(f"Overall TestSuite Outcome: {outcome}")
        self.jira(outcome)
        error = None
        if not self.results:
            logger.warning("[{}] No test results to publish".format(TESTRAIL_PREFIX))
            raise Exception("No test results to publish in TestRail")
        for result in self.results:
            if result["status_id"] != 1:
                result["defects"] = self.issue_id
        tests_list = [str(result["case_id"]) for result in self.results]
        try:
            os.makedirs(RESULTS_DIR, exist_ok=True)
            with open(RESULTS_FILE_PATH, "w") as file:
                file.write(str(session.results))
            logger.info(f"Test results saved to: {RESULTS_FILE_PATH}")
        except Exception as e:
            logger.error(f"Failed to save test results: {e}")
        logger.info(f"Test results saved to: {RESULTS_FILE_PATH}")
        logger.info(
            "[{}] Testcases to publish: {}".format(
                TESTRAIL_PREFIX, ", ".join(tests_list)
            )
        )
        if self.testrun_id:
            self.add_results(self.testrun_id)
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
            data = {
                "case_id": test_id,
                "status_id": status,
                "comment": comment,
                "duration": duration,
                "defects": defects,
                "test_parametrize": test_parametrize,
            }
            self.results.append(data)

    def add_results(self, testrun_id):
        """
        Add results one by one to improve errors handling.

        :param testrun_id: Id of the testrun to feed

        """
        # unicode converter for compatibility of python 2 and 3
        try:
            converter = unicode
        except NameError:
            converter = lambda s, c: str(bytes(s, "utf-8"), c)
        # Results are sorted by 'case_id' and by 'status_id' (worst result at the end)

        # Comment sort by status_id due to issue with pytest-rerun failures,
        # for details refer to issue https://github.com/allankp/pytest-testrail/issues/100
        # self.results.sort(key=itemgetter('status_id'))
        self.results.sort(key=itemgetter("case_id"))

        # Manage case of "blocked" testcases
        if self.publish_blocked is False:
            logger.warning(
                '[{}] Option "Don\'t publish blocked testcases" activated'.format(
                    TESTRAIL_PREFIX
                )
            )
            blocked_tests_list = [
                test.get("case_id")
                for test in self.get_tests(testrun_id)
                if test.get("status_id") == TESTRAIL_TEST_STATUS["blocked"]
            ]
            logger.warning(
                "[{}] Blocked testcases excluded: {}".format(
                    TESTRAIL_PREFIX, ", ".join(str(elt) for elt in blocked_tests_list)
                )
            )
            self.results = [
                result
                for result in self.results
                if result.get("case_id") not in blocked_tests_list
            ]

        # prompt enabling include all test cases from test suite when creating test run
        if self.include_all:
            logger.warning(
                '[{}] Option "Include all testcases from test suite for test run" activated'.format(
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
        if error:
            logger.warning(
                '[{}] Info: Testcases not published for following reason: "{}"'.format(
                    TESTRAIL_PREFIX, error
                )
            )

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
            logger.error(
                '[{}] Failed to create testrun: "{}"'.format(TESTRAIL_PREFIX, error)
            )
        else:
            self.testrun_id = response["id"]
            logger.warning(
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
            logger.error(
                '[{}] Failed to close test run: "{}"'.format(TESTRAIL_PREFIX, error)
            )
        else:
            logger.warning(
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
            logger.error(
                '[{}] Failed to close test plan: "{}"'.format(TESTRAIL_PREFIX, error)
            )
        else:
            logger.warning(
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
            logger.error(
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
            logger.error(
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
            logger.error(
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
            logger.error(
                '[{}] Failed to get tests: "{}"'.format(TESTRAIL_PREFIX, error)
            )
            return None
        return response
