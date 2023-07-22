#!/usr/bin/python3
"""Mass submit sample files to VMRay Analyzer"""


import argparse
import io
import os
import sys


FILE = os.path.abspath(os.path.realpath(__file__))


try:
    # try to import VMRay REST API
    from vmray.rest_api import VMRayRESTAPI
except ImportError:
    # if VMRAY REST API is not installed, try relative import
    sys.path.append(os.path.join(os.path.dirname(FILE), ".."))
    from vmray.rest_api import VMRayRESTAPI


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


def mass_submit_files(api, args):
    files = [
        filename for filename in
        [os.path.join(args.samples_dir, filename) for filename in os.listdir(args.samples_dir)]
        if os.path.isfile(filename)
    ]

    print("Found {} sample files in folder \"{}\"".format(len(files), args.samples_dir))

    print("Submitting sample files")
    for filename in files:
        with io.open(filename, "rb") as fobj:
            params = {
                "sample_file": fobj,
            }

            if args.comment is not None:
                params["comment"] = args.comment
            if args.prescript_file is not None:
                params["prescript_file"] = args.prescript_file
            if args.reanalyze is not None:
                params["reanalyze"] = args.reanalyze
            if args.shareable is not None:
                params["shareable"] = args.shareable
            if args.user_config is not None:
                params["user_config"] = args.user_config

            api.call("POST", "/rest/sample/submit", params)

    print("Done. Please check the web interface to see the running jobs.")


def main():
    # set up argument parser
    parser = argparse.ArgumentParser(description="Mass submit sample files to VMRay Analyzer")

    # arguments
    parser.add_argument("server", type=str, help="Server address")
    parser.add_argument("api_key", type=str, help="API key to use")
    parser.add_argument("--no_verify", "-n", action="store_true", help="Do not verify SSL certificate")

    parser.add_argument("samples_dir", type=str, help="Submit all files in this directory")
    parser.add_argument("--comment", type=str, help="Submission comment")
    parser.add_argument("--prescript_file", type=UnicodeFileType("rb"), help="Path to prescript file")
    parser.add_argument("--reanalyze", "-r", action="store_true", help="Reanalyze samples if analyses already exist")
    parser.add_argument("--no_reanalyze", action="store_false", dest="reanalyze",
                        help="Do not reanalyze sample if analyses already exist")
    parser.add_argument("--shareable", action="store_true", help="Samples can be shared with public")
    parser.add_argument("--not_shareable", action="store_false", dest="shareable",
                        help="Sample cannot be shared with public sample")
    parser.add_argument("--user_config", type=str, help="User configuration")

    # parse args
    args = parser.parse_args()

    # create VMRay REST API object
    api = VMRayRESTAPI(args.server, args.api_key, not args.no_verify)

    # perform API call
    return mass_submit_files(api, args)


if __name__ == "__main__":
    main()
