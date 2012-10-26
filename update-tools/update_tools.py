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
# Various APIs for building updates (both OTA and FOTA) for FxOS

import hashlib
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

class MarTool(object):
    def __init__(self):
        host_dir = "linux-x86"
        if platform.system() == "Darwin":
            host_dir = "darwin-x86"

        self.mar = os.path.join(prebuilt_dir, host_dir, "mar")
        if not os.path.exists(self.mar):
            raise Exception("Couldn't find %s " % self.mar)

    def get_path(self):
        return self.mar

    def list_entries(self, mar_path):
        result = run_command([self.mar, "-t", mar_path])
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
        shutil.copy(signed_zip, mar_dir)

        precomplete = os.path.join(mar_dir, "precomplete")
        open(precomplete, "w").write("")

        run_command([make_full_update, output_mar, mar_dir],
            env={"MAR": mar_tool.get_path()})

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

