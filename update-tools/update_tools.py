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
# APIs for building and testing OTA and FOTA updates for FxOS

import hashlib
import optparse
import os
import platform
import re
import shutil
import StringIO
import subprocess
import sys
import tempfile
import xml.dom.minidom as minidom
import zipfile

# This needs to be run from within a B2G checkout
this_dir = os.path.abspath(os.path.dirname(__file__))
b2g_dir = os.path.dirname(os.path.dirname(this_dir))

# TODO pull this from load-config.sh / GECKO_PATH
gecko_dir = os.path.join(b2g_dir, "gecko")
prebuilt_dir = os.path.join(this_dir, "prebuilt")

def run_command(*args, **kwargs):
    try:
        return subprocess.check_output(*args, **kwargs)
    except subprocess.CalledProcessError, e:
        raise Exception("Process returned error code %d: %s" % \
                        (e.returncode, " ".join(e.cmd)))

class PrebuiltTool(object):
    def __init__(self, name):
        host_dir = "linux-x86"
        if platform.system() == "Darwin":
            host_dir = "darwin-x86"

        self.tool = os.path.join(prebuilt_dir, host_dir, name)
        if not os.path.exists(self.tool):
            raise Exception("Couldn't find %s " % self.tool)

    def get_tool(self):
        return self.tool

    def run(self, *args):
        return run_command((self.tool,) + args)

class AdbTool(PrebuiltTool):
    DEVICE   = ("-d")
    EMULATOR = ("-e")

    def __init__(self, device=None):
        PrebuiltTool.__init__(self, "adb")
        self.adb_args = ()
        if device in (self.DEVICE, self.EMULATOR):
            self.adb_args = device
        elif device:
            self.adb_args = ("-s", device)

    def run(self, *args):
        adb_args = self.adb_args + args
        return PrebuiltTool.run(self, *adb_args)

    def shell(self, *args):
        return self.run("shell", *args)

    def push(self, *args):
        self.run("push", *args)

    def file_exists(self, remote_file):
        result = self.shell("ls %s 2>/dev/null 1>/dev/null; echo $?" % \
                            remote_file)
        return result.strip() == "0"

    def get_pid(self, process):
        result = self.shell(
            "toolbox ps %s | (read header; read user pid rest; echo -n $pid)" % \
                process)

        pid = result.strip()
        if len(pid) == 0:
            return None
        return pid

class MarTool(PrebuiltTool):
    def __init__(self):
        PrebuiltTool.__init__(self, "mar")

    def list_entries(self, mar_path):
        result = self.run("-t", mar_path)
        entries = []
        for line in result.splitlines():
            words = re.split("\s+", line)
            if len(words) < 3: continue
            if words[0] == "SIZE": continue
            entries.append(words[2])
        return entries

    def is_gecko_mar(self, mar_path):
        return not self.is_fota_mar(mar_path)

    def is_fota_mar(self, mar_path):
        entries = self.list_entries(mar_path)
        return "update.zip" in entries

class FotaZip(zipfile.ZipFile):
    UPDATE_BINARY  = "META-INF/com/google/android/update-binary"
    UPDATER_SCRIPT = "META-INF/com/google/android/updater-script"
    MANIFEST_MF    = "META-INF/MANIFEST.MF"
    CERT_SF        = "META-INF/CERT.SF"

    def __init__(self, path):
        zipfile.ZipFile.__init__(self, path, "r")

    def has_entry(self, entry):
        try:
            self.getinfo(entry)
            return True
        except: return False

    def validate(self, signed=False):
        entries = (self.UPDATE_BINARY, self.UPDATER_SCRIPT)
        if signed:
            entries += (self.MANIFEST_MF, self.CERT_SF)

        if not all(map(self.has_entry, entries)):
            raise Exception("Update zip is missing expected file: %s" % entry)

class FotaZipBuilder(object):
    def build_unsigned_zip(self, update_dir, output_zip):
        if not os.path.exists(update_dir):
            raise Exception("Update dir doesn't exist: %s" % update_dir)

        update_zipfile = zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED)

        for root, dirs, files in os.walk(update_dir):
            for name in files:
                file_path = os.path.join(root, name)
                relative_path = os.path.relpath(file_path, update_dir)
                update_zipfile.write(file_path, relative_path)

        update_zipfile.close()

    def sign_zip(self, unsigned_zip, public_key, private_key, output_zip):
        try:
            java = subprocess.check_output(["which", "java"]).strip()
        except subprocess.CalledProcessError, e:
            raise Exception("java is required to be on your PATH for signing")

        with FotaZip(unsigned_zip) as fota_zip:
            fota_zip.validate()

        if not os.path.exists(private_key):
            raise Exception("Private key doesn't exist: %s" % private_key)

        if not os.path.exists(public_key):
            raise Exception("Public key doesn't exist: %s" % public_key)

        signapk_jar = os.path.join(prebuilt_dir, "signapk.jar")

        run_command([java, "-Xmx2048m", "-jar", signapk_jar,
            "-w", public_key, private_key, unsigned_zip, output_zip])

class FotaMarBuilder(object):
    def __init__(self):
        self.stage_dir = tempfile.mkdtemp()

    def __del__(self):
        shutil.rmtree(self.stage_dir)

    def build_mar(self, signed_zip, output_mar):
        with FotaZip(signed_zip) as fota_zip:
            fota_zip.validate(signed=True)

        mar_tool = MarTool()
        make_full_update = os.path.join(gecko_dir, "tools",
            "update-packaging", "make_full_update.sh")
        if not os.path.exists(make_full_update):
            raise Exception("Couldn't find %s " % make_full_update)

        mar_dir = os.path.join(self.stage_dir, "mar")
        os.mkdir(mar_dir)

        # Inside the FOTA MAR, the update needs to be called "update.zip"
        shutil.copy(signed_zip, os.path.join(mar_dir, "update.zip"))

        precomplete = os.path.join(mar_dir, "precomplete")
        open(precomplete, "w").write("")

        run_command([make_full_update, output_mar, mar_dir],
            env={"MAR": mar_tool.get_tool()})

class UpdateXmlBuilder(object):
    DEFAULT_URL_TEMPLATE = "http://localhost/%(patch_name)s"
    DEFAULT_UPDATE_TYPE = "minor"
    DEFAULT_APP_VERSION = "99.0"
    DEFAULT_PLATFORM_VERSION = "99.0"
    DEFAULT_LICENSE_URL = "http://www.mozilla.com/test/sample-eula.html"
    DEFAULT_DETAILS_URL = "http://www.mozilla.com/test/sample-details.html"

    def __init__(self, complete_mar=None, partial_mar=None, url_template=None,
                 update_type=None, app_version=None, platform_version=None,
                 license_url=None, details_url=None, is_fota_update=False):

        if complete_mar is None and partial_mar is None:
            raise Exception("either complete_mar or partial_mar is required")

        self.complete_mar = complete_mar
        self.partial_mar = partial_mar
        self.url_template = url_template or self.DEFAULT_URL_TEMPLATE
        self.update_type = update_type or self.DEFAULT_UPDATE_TYPE
        self.app_version = app_version or self.DEFAULT_APP_VERSION
        self.platform_version = platform_version or self.DEFAULT_PLATFORM_VERSION
        self.license_url = license_url or self.DEFAULT_LICENSE_URL
        self.details_url = details_url or self.DEFAULT_DETAILS_URL
        self.is_fota_update = is_fota_update

    def sha512(self, patch_path):
        patch_hash = hashlib.sha512()
        with open(patch_path, "r") as patch_file:
            data = patch_file.read(512)
            while len(data) > 0:
                patch_hash.update(data)
                data = patch_file.read(512)

        return patch_hash.hexdigest()

    def build_patch(self, patch_type, patch_file):
        patch = self.doc.createElement("patch")
        patch.setAttribute("type", patch_type)

        template_args = self.__dict__.copy()
        template_args["patch_name"] = os.path.basename(patch_file)
        patch.setAttribute("URL", self.url_template % template_args)

        patch.setAttribute("hashFunction", "SHA512")
        patch.setAttribute("hashValue", self.sha512(patch_file))
        patch.setAttribute("size", str(os.stat(patch_file).st_size))
        return patch

    def build_xml(self):
        impl = minidom.getDOMImplementation()
        self.doc = impl.createDocument(None, "updates", None)

        updates = self.doc.documentElement
        update = self.doc.createElement("update")
        updates.appendChild(update)

        update.setAttribute("type", self.update_type)
        update.setAttribute("appVersion", self.app_version)
        update.setAttribute("version", self.platform_version)
        update.setAttribute("licenseURL", self.license_url)
        update.setAttribute("detailsURL", self.details_url)

        if self.is_fota_update:
            update.setAttribute("isOSUpdate", "true")

        if self.complete_mar:
            complete_patch = self.build_patch("complete", self.complete_mar)
            update.appendChild(complete_patch)

        if self.partial_mar:
            partial_patch = self.build_patch("partial", self.partial_mar)
            update.appendChild(partial_patch)

        return self.doc.toprettyxml()

class UpdateXmlOptions(optparse.OptionParser):
    def __init__(self):
        optparse.OptionParser.__init__(self, usage="%prog [options] (update.mar)")
        self.add_option("-c", "--complete-mar", dest="complete_mar", metavar="MAR",
            default=None, help="Path to a 'complete' MAR. This can also be " +
                               "provided as the first argument. Either " +
                               "--complete-mar or --partial-mar must be provided.")

        self.add_option("-p", "--partial-mar", dest="partial_mar", metavar="MAR",
            default=None, help="Path to a 'partial' MAR")

        self.add_option("-o", "--output", dest="output", metavar="FILE",
            default=None, help="Place to generate the update XML. Default: " +
                               "print XML to stdout")

        self.add_option("-u", "--url-template", dest="url_template", metavar="URL",
            default=None, help="A template for building URLs in the update.xml. " +
                               "Default: http://localhost/%(patch_name)s")

        self.add_option("-t", "--update-type", dest="update_type",
            default="minor", help="The update type. Default: minor")

        self.add_option("-v", "--app-version", dest="app_version",
            default=None, help="The application version of this update. " +
                               "Default: 99.0")
        self.add_option("-V", "--platform-version", dest="platform_version",
            default=None, help="The platform version of this update. Default: 99.0")

        self.add_option("-l", "--license-url", dest="license_url",
            default=None, help="The license URL of this update. Default: " +
                                UpdateXmlBuilder.DEFAULT_LICENSE_URL)
        self.add_option("-d", "--details-url", dest="details_url",
            default=None, help="The details URL of this update. Default: " +
                                UpdateXmlBuilder.DEFAULT_DETAILS_URL)

        self.add_option("-O", "--fota-update", dest="fota_update",
            action="store_true", default=None,
            help="The complete MAR contains a FOTA update. " +
                 "Default: detect.\nNote: only 'complete' MARs can be FOTA updates.")

    def parse_args(self):
        options, args = optparse.OptionParser.parse_args(self)
        if not options.complete_mar and len(args) > 0:
            options.complete_mar = args[0]

        if not options.complete_mar and not options.partial_mar:
            self.print_help()
            print >>sys.stderr, \
                "Error: At least one of --complete-mar or --partial-mar is required."
            sys.exit(1)

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

        self.is_fota_update = fota_update
        self.options, self.args = options, args
        return options, args

    def get_output_xml(self):
        return self.options.output

    def get_complete_mar(self):
        return self.options.complete_mar

    def get_partial_mar(self):
        return self.options.partial_mar

    def build_xml(self):
        option_keys = ("complete_mar", "partial_mar", "url_template",
            "update_type", "app_version", "platform_version", "license_url",
            "details_url")

        kwargs = {"is_fota_update": self.is_fota_update}
        for key in option_keys:
            kwargs[key] = getattr(self.options, key)

        builder = UpdateXmlBuilder(**kwargs)
        return builder.build_xml()

class TestUpdate(object):
    REMOTE_BIN_DIR     = "/data/local/bin"
    REMOTE_BUSYBOX     = REMOTE_BIN_DIR + "/busybox"
    LOCAL_BUSYBOX      = os.path.join(prebuilt_dir, "gonk", "busybox-armv6l")
    REMOTE_HTTP_ROOT   = "/data/local/b2g-updates"
    REMOTE_PROFILE_DIR = "/data/b2g/mozilla"
    UPDATE_URL         = "http://localhost/update.xml"

    def __init__(self, update_xml, complete_mar=None, partial_mar=None):
        self.adb = AdbTool()
        self.stage_dir = tempfile.mkdtemp()
        self.update_xml = update_xml

        if complete_mar is None and partial_mar is None:
            raise Exception(
                "At least one of complete_mar or partial_mar is required")

        self.complete_mar = complete_mar
        self.partial_mar = partial_mar


    def __del__(self):
        shutil.rmtree(self.stage_dir)

    def test_update(self):
        output_xml = os.path.join(self.stage_dir, "update.xml")
        with open(output_xml, "w") as out_file:
            out_file.write(self.update_xml)

        self.push_busybox()
        self.push_update_site()
        self.start_http_server()
        self.override_update_url()
        self.restart_b2g()

    def push_busybox(self):
        if self.adb.file_exists(self.REMOTE_BUSYBOX):
            print "Busybox already found at %s" % self.REMOTE_BUSYBOX
            return

        print "Busybox not found, pushing to %s" % self.REMOTE_BUSYBOX
        self.adb.shell("mkdir", "-p", self.REMOTE_BIN_DIR)
        self.adb.push(self.LOCAL_BUSYBOX, self.REMOTE_BUSYBOX)
        self.adb.shell("chmod", "755", self.REMOTE_BUSYBOX)

    def push_update_site(self):
        if self.complete_mar:
            shutil.copy(self.complete_mar, self.stage_dir)

        if self.partial_mar:
            shutil.copy(self.partial_mar, self.stage_dir)

        self.adb.push(self.stage_dir, self.REMOTE_HTTP_ROOT)

    def start_http_server(self):
        busybox_pid = self.adb.get_pid("busybox")
        if busybox_pid is not None:
            print "Busybox HTTP server already running, PID: %s" % busybox_pid
            return

        print "Starting Busybox HTTP server"
        self.adb.shell(self.REMOTE_BUSYBOX,
            "httpd", "-h", self.REMOTE_HTTP_ROOT)

        busybox_pid = self.adb.get_pid("busybox")
        if busybox_pid is not None:
            print "Busybox HTTP server now running. Root: %s, PID: %s" % \
                (self.REMOTE_HTTP_ROOT, busybox_pid)
        else:
            print >>sys.stderr, "Error: Busybox HTTP server PID not running"
            sys.exit(1)

    def override_update_url(self):
        result = self.adb.shell("ls", "-l", self.REMOTE_PROFILE_DIR)
        profile_dir = None
        for line in result.splitlines():
            match = re.search(r"([^ ]+\.default)", line)
            if not match: continue
            profile_dir = self.REMOTE_PROFILE_DIR + "/" + match.group(1)

        if not profile_dir:
            raise Exception("Unable to find profile dir in %s" % \
                            self.REMOTE_PROFILE_DIR)

        url_pref = "app.update.url.override"
        prefs_js = profile_dir + "/prefs.js"

        print "Overriding update URL in %s to %s" % (prefs_js, self.UPDATE_URL)
        self.adb.shell("echo 'user_pref(\"%s\", \"%s\");' >> %s" % \
                       (url_pref, self.UPDATE_URL, prefs_js))

    def restart_b2g(self):
        print "Restarting B2G"
        self.adb.shell("stop b2g; start b2g")
