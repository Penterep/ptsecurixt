#!/usr/bin/python3
"""
    Copyright (c) 2023 Penterep Security s.r.o.

    ptsecurixt - security.txt finder

    ptsecurixt is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ptsecurixt is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with ptsecurixt.  If not, see <https://www.gnu.org/licenses/>.
"""


import argparse
import os
import sys; sys.path.append(__file__.rsplit("/", 1)[0])
import re
import urllib

import requests

from _version import __version__
from ptlibs import ptjsonlib, ptprinthelper, ptmisclib, ptnethelper


class PtSecurixt:
    def __init__(self, args):
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.headers     = ptnethelper.get_request_headers(args)
        self.proxies     = {"http": args.proxy, "https": args.proxy}
        self.use_json    = args.json
        self.redirects   = args.redirects
        self.timeout     = args.timeout
        self.cache       = args.cache
        self.url         = self._adjust_url(args.url)

    def run(self) -> None:
        """Main method"""
        known_places = ["security.txt", ".well-known/security.txt"]
        result = [self._find_security_txt(location) for location in known_places]
        if not any(result):
            ptprinthelper.ptprint(f"\r{' '*100}\r", "", not self.use_json, end="")
            ptprinthelper.ptprint(f"security.txt file was not found", "VULN", not self.use_json)
            self.ptjsonlib.add_vulnerability("MISSING-SECURITY-TXT")

        self.ptjsonlib.set_status("ok")
        ptprinthelper.ptprint(self.ptjsonlib.get_result_json(), "", self.use_json)

    def _find_security_txt(self, location: str) -> bool:
        """Returns True when found"""
        url = self.url + location
        ptprinthelper.ptprint(f"\r{' '*(30+len(url))}\r[*] Searching: {url}", "TITLE", not self.use_json, end=f"", colortext=True)
        try:
            response = ptmisclib.load_url_from_web_or_temp(url, method="GET", headers=self.headers, proxies=self.proxies, timeout=self.timeout, redirects=self.redirects, verify=False, cache=self.cache, dump_response=False)
        except requests.exceptions.RequestException as e:
            self._break_carriage_return()
            self.ptjsonlib.end_error(f"Cannot connect to website - {e}", self.use_json)
        if response.status_code == 200 and "text/plain" in response.headers["content-type"]:
            self._break_carriage_return()
            ptprinthelper.ptprint(f"Found security.txt file", "OK", not self.use_json)
            ptprinthelper.ptprint(f"File contents:", "TITLE", not self.use_json)
            file_contents = response.text.encode('ascii', 'ignore').decode()
            ptprinthelper.ptprint(file_contents, "", not self.use_json, newline_above=True)
            if self.use_json:
                self.ptjsonlib.add_node(self.ptjsonlib.create_node_object("webpage", properties={"url": url, "name": os.path.split(response.url)[-1], "WebPageType": "security_txt"}))
            return True

    def _adjust_url(self, url: str) -> str:
        o = urllib.parse.urlparse(url)
        if not re.match("https?$", o.scheme):
            self.ptjsonlib.end_error("Missing or wrong scheme - only HTTP/HTTPS schemas are supported", self.use_json)
        if not o.netloc:
            self.ptjsonlib.end_error("Invalid URL provided", self.use_json)
        return urllib.parse.urlunparse((o.scheme, o.netloc, "/", "", "", ""))

    def _break_carriage_return(self) -> None:
        ptprinthelper.ptprint(f"\n", "", not self.use_json)


def get_help():
    return [
        {"description": ["Script searches for security.txt file in known locations"]},
        {"usage": ["ptsecurixt <options>"]},
        {"usage_example": [
            "ptsecurixt -u https://www.example.com",
        ]},
        {"options": [
            ["-u",  "--url",                    "<url>",            "Connect to URL"],
            ["-p",  "--proxy",                  "<proxy>",          "Set proxy (e.g. http://127.0.0.1:8080)"],
            ["-T",  "--timeout",                "",                 "Set timeout (default 10)"],
            ["-c",  "--cookie",                 "<cookie>",         "Set cookie"],
            ["-ua", "--user-agent",             "<ua>",             "Set User-Agent header"],
            ["-H",  "--headers",                "<header:value>",   "Set custom header(s)"],
            ["-r",  "--redirects",              "",                 "Follow redirects (default False)"],
            ["-C",  "--cache",                  "",                 "Cache HTTP communication (load from tmp in future)"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]


def parse_args():
    parser = argparse.ArgumentParser(add_help="False", description="ptseruxt <options>")
    parser.add_argument("-u",  "--url",            type=str, required=True)
    parser.add_argument("-p",  "--proxy",          type=str)
    parser.add_argument("-T",  "--timeout",        type=int, default=10)
    parser.add_argument("-ua", "--user-agent",     type=str, default="Penterep Tools")
    parser.add_argument("-c",  "--cookie",         type=str)
    parser.add_argument("-H",  "--headers",        type=ptmisclib.pairs, nargs="+")
    parser.add_argument("-r",  "--redirects",      action="store_true")
    parser.add_argument("-C",  "--cache",          action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args = parser.parse_args()
    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)
    return args


def main():
    global SCRIPTNAME
    SCRIPTNAME = "ptsecurixt"
    requests.packages.urllib3.disable_warnings()
    requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    args = parse_args()
    script = PtSecurixt(args)
    script.run()


if __name__ == "__main__":
    main()
