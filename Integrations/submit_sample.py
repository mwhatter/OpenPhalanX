#!/usr/bin/python3
"""Submit sample to VMRay Analyzer"""


import argparse
import json
import os
import sys
import time


FILE = os.path.abspath(os.path.realpath(__file__))


try:
    # try to import VMRay REST API
    from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError
except ImportError:
    # if VMRAY REST API is not installed, try relative import
    sys.path.append(os.path.join(os.path.dirname(FILE), ".."))
    from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError


class UnicodeFileType(argparse.FileType):
    def __init__(self, *args, **kwargs):
        argparse.FileType.__init__(self, *args, **kwargs)

    def __call__(self, string):
        try:
            sanitized_str = str(string)
        except UnicodeDecodeError:
            import ast
            sanitized_str = str(ast.literal_eval("u" + repr(string)))

        return argparse.FileType.__call__(self, sanitized_str)


def wait_submission(api, submit_data, sleep_interval=1):
    pending_submissions = list(submit_data["submissions"])
    while True:
        # for all pending submissions, check if they have finished
        for submission in list(pending_submissions):
            try:
                submission_data = api.call("GET", "/rest/submission/{}".format(submission["submission_id"]))

                if submission_data["submission_finished"]:
                    pending_submissions.remove(submission)
                else:
                    # sleep already
                    break
            except VMRayRESTAPIError:
                # try again in case of error
                break

        if not pending_submissions:
            break

        time.sleep(sleep_interval)


def old_wait_submission(api, submit_data):
    # this was the preferred method to wait for all jobs to finish before 1.12.0

    open_jobs = submit_data["jobs"]
    while open_jobs:
        # check if job finished
        # this examples assumes that jobs are never deleted
        check_jobs = list(open_jobs)
        open_jobs = []
        for job in check_jobs:
            try:
                api.call("GET", "/rest/analysis/job/{}".format(job["job_id"]))
            except VMRayRESTAPIError as exc:
                if exc.status_code == 404:
                    # job has not finished yet
                    open_jobs.append(job)
                else:
                    raise

        time.sleep(1)


def submit_sample(api, args):
    # add specified parameters
    params = {}
    if args.archive_action is not None:
        params["archive_action"] = args.archive_action
    if args.archive_password is not None:
        params["archive_password"] = args.archive_password
    if args.cmd_line is not None:
        params["cmd_line"] = args.cmd_line
    if args.comment is not None:
        params["comment"] = args.comment
    if args.compound_sample is not None:
        params["compound_sample"] = args.compound_sample
    if args.entry_point is not None:
        params["entry_point"] = args.entry_point
    if args.jobrule_entries is not None:
        params["jobrule_entries"] = args.jobrule_entries
    if args.prescript_file is not None:
        params["prescript_file"] = args.prescript_file
    if args.reanalyze is not None:
        params["reanalyze"] = args.reanalyze
    if args.sample_file is not None:
        params["sample_file"] = args.sample_file
    if args.sample_type is not None:
        params["sample_type"] = args.sample_type
    if args.shareable is not None:
        params["shareable"] = args.shareable
    if args.user_config is not None:
        params["user_config"] = args.user_config

    data = api.call("POST", "/rest/sample/submit", params)
    print(json.dumps(data, indent=2))

    if args.wait:
        if data["submissions"] and ("submission_finished" in data["submissions"][0]):
            print("Waiting for jobs to complete")
            wait_submission(api, data)
        else:
            print("Waiting for jobs to complete (old method)")
            old_wait_submission(api, data)

        print("All jobs have finished")


def main():
    # set up argument parser
    parser = argparse.ArgumentParser(description="Submit sample to VMRay Analyzer")

    # arguments
    parser.add_argument("server", type=str, help="Server address")
    parser.add_argument("api_key", type=str, help="API key to use")

    parser.add_argument("sample_file", type=UnicodeFileType("rb"), help="Path to sample file")
    parser.add_argument("--no_verify", "-n", action="store_true", help="Do not verify SSL certificate")
    parser.add_argument("--archive_action", type=str, help="Archive action")
    parser.add_argument("--archive_password", type=str, help="Archive password")
    parser.add_argument("--cmd_line", type=str, help="Command line")
    parser.add_argument("--comment", type=str, help="Submission comment")
    parser.add_argument("--compound_sample", action="store_true", help="Treat sample as compound sample")
    parser.add_argument("--no_compound_sample", action="store_false", dest="compound_sample",
                        help="Do not treat sample file as compound sample")
    parser.add_argument("--entry_point", type=str, help="Entry point")
    parser.add_argument("--jobrule_entries", type=str, help="Jobrule entries")
    parser.add_argument("--prescript_file", type=UnicodeFileType("rb"), help="Path to prescript file")
    parser.add_argument("--reanalyze", action="store_true", help="Reanalyze sample if analyses already exist")
    parser.add_argument("--no_reanalyze", action="store_false", dest="reanalyze",
                        help="Reanalyze sample if analyses already exist")
    parser.add_argument("--sample_type", type=str, help="Use this sample type")
    parser.add_argument("--shareable", action="store_true", help="Sample can be shared with public")
    parser.add_argument("--not_shareable", action="store_false", dest="shareable",
                        help="Sample cannot be shared with public sample")
    parser.add_argument("--user_config", type=str, help="User configuration")
    parser.add_argument("--wait", "-w", action="store_true", help="Wait for jobs to finish before exiting")

    # parse args
    args = parser.parse_args()

    # create VMRay REST API object
    api = VMRayRESTAPI(args.server, args.api_key, not args.no_verify)

    # perform API call
    return submit_sample(api, args)


if __name__ == "__main__":
    main()
