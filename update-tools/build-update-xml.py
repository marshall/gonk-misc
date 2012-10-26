#!/usr/bin/env python
#
# Copyright (C) 2012 Mozilla Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Build a FxOS update.xml for testing.

import optparse
import os
import sys
from update_tools import MarTool, UpdateXmlBuilder

def build_xml(options, is_fota_update, output_xml):
    option_keys = ("complete_mar", "partial_mar", "url_template",
        "update_type", "app_version", "platform_version", "license_url",
        "details_url")

    kwargs = {"is_fota_update": is_fota_update}
    for key in option_keys:
        kwargs[key] = getattr(options, key)

    builder = UpdateXmlBuilder(**kwargs)
    xml = builder.build_xml()

    if output_xml:
        with open(output_xml, "w") as out_file:
            out_file.write(xml)
    else:
        print xml

def is_fota_update(options):
    fota_update = False
    if options.fota_update is None and options.complete_mar:
        if not os.path.exists(options.complete_mar):
            print >>sys.stderr, \
                "Error: MAR doesn't exist: %s" % options.complete_mar
            sys.exit(1)

        mar_tool = MarTool()
        fota_update = mar_tool.is_fota_mar(options.complete_mar)
    elif options.fota_update:
        fota_update = True
        if not options.complete_mar:
            print >>sys.stderr, \
                "Error: --fota-update provided without a --complete-mar"
            sys.exit(1)

    if options.partial_mar and fota_update:
        print >>sys.stderr, \
            "Warning: --partial-mar ignored for FOTA updates"
        options.partial_mar = None

    return fota_update

def main():
    parser = optparse.OptionParser(usage="%prog [options] (update.mar)")
    parser.add_option("-c", "--complete-mar", dest="complete_mar", metavar="MAR",
        default=None, help="Path to a 'complete' MAR. This can also be " +
                           "provided as the first argument. Either " +
                           "--complete-mar or --partial-mar must be provided.")

    parser.add_option("-p", "--partial-mar", dest="partial_mar", metavar="MAR",
        default=None, help="Path to a 'partial' MAR")

    parser.add_option("-o", "--output", dest="output", metavar="FILE",
        default=None, help="Place to generate the update XML. Default: " +
                           "print XML to stdout")

    parser.add_option("-u", "--url-template", dest="url_template", metavar="URL",
        default=None, help="A template for building URLs in the update.xml. " +
                           "Default: http://localhost/%(patch_name)s")

    parser.add_option("-t", "--update-type", dest="update_type",
        default="minor", help="The update type. Default: minor")

    parser.add_option("-v", "--app-version", dest="app_version",
        default=None, help="The application version of this update. " +
                            "Default: 99.0")
    parser.add_option("-V", "--platform-version", dest="platform_version",
        default=None, help="The platform version of this update. Default: 99.0")

    parser.add_option("-l", "--license-url", dest="license_url",
        default=None, help="The license URL of this update. Default: " +
                           UpdateXmlBuilder.DEFAULT_LICENSE_URL)
    parser.add_option("-d", "--details-url", dest="details_url",
        default=None, help="The details URL of this update. Default: " +
                           UpdateXmlBuilder.DEFAULT_DETAILS_URL)

    parser.add_option("-O", "--fota-update", dest="fota_update",
        action="store_true", default=None,
        help="The complete MAR contains a FOTA update. " +
             "Default: detect.\nNote: only 'complete' MARs can be FOTA updates.")

    options, args = parser.parse_args()
    if not options.complete_mar and len(args) > 0:
        options.complete_mar = args[0]

    if not options.complete_mar and not options.partial_mar:
        parser.print_help()
        print >>sys.stderr, \
            "Error: At least one of --complete-mar or --partial-mar is required."
        sys.exit(1)

    try:
        build_xml(options, is_fota_update(options), options.output)
    except Exception, e:
        print >>sys.stderr, "Error: %s" % e
        sys.exit(1)

if __name__ == "__main__":
    main()
