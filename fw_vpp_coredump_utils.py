################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2021  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import sys
import time
import os
import glob
import tarfile
import errno
import fwglobals
import threading
import shutil
import datetime


FW_VPP_COREDUMP_LOCATION = "/var/crash/"
FW_VPP_COREDUMP_START_STR = "core-vpp"
FW_VPP_COREDUMP_END_STR = "-dump"
FW_MAX_CORE_RETAIN_LIMIT = 3
FW_VPP_COREDUMP_LOCK = threading.Lock()
FW_APT_REPO_FILE = "/etc/apt/sources.list.d/flexiwan*source.list"


class FwVppCoredumpProcess(threading.Thread):

    def __init__(self, corefiles):
        threading.Thread.__init__(self)
        self.corefiles = corefiles

    def __vpp_coredump_compress(self, corefile):

        # Make core and tar to contain readable core timestamp
        filename_parse = corefile.split("-")
        epoch_ts = int(filename_parse[len(filename_parse) - 2])
        ts_str = datetime.datetime.fromtimestamp(epoch_ts).strftime('%Y%m%d_%H%M%S')
        corefile_ts_str = corefile + "-" +  ts_str
        os.rename(corefile, corefile_ts_str)
        out_tar_filename = corefile_ts_str + ".tar.gz"

        # Write to temp file
        temp_out_tar_filename = FW_VPP_COREDUMP_LOCATION + "TEMP.core." + ts_str
        tar_file = tarfile.open(temp_out_tar_filename, "w:gz")
        tar_file.add(corefile_ts_str, arcname=os.path.basename(corefile_ts_str))

        # Include version and apt-repo file as part of coredump
        ts_str = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d_%H%M%S')
        version_file = FW_VPP_COREDUMP_LOCATION + "fw_version-" + ts_str + ".yaml"
        shutil.copy2(fwglobals.g.VERSIONS_FILE, version_file)
        tar_file.add(version_file, arcname=os.path.basename(version_file))
        repo_file = FW_VPP_COREDUMP_LOCATION + "fw_repo-" + ts_str + ".list"
        for filepath in glob.glob(FW_APT_REPO_FILE):
            shutil.copy2(filepath, repo_file)
            break
        tar_file.add(repo_file, arcname=os.path.basename(repo_file))
        tar_file.close()

        # replace / remove temp files
        os.rename(temp_out_tar_filename, out_tar_filename)
        os.remove(corefile_ts_str)
        os.remove(version_file)
        os.remove(repo_file)
        fwglobals.log.info("vpp_coredump_compress: compressed : %s" % (corefile))
        return out_tar_filename


    def __vpp_coredump_limit_cores(self):

        files = glob.glob((FW_VPP_COREDUMP_LOCATION + FW_VPP_COREDUMP_START_STR + "*"))
        filenames = sorted(files, key=lambda t: -os.stat(t).st_ctime)
        count = 0
        for filename in filenames:
            if tarfile.is_tarfile(filename):
                count = count +1
                if count > FW_MAX_CORE_RETAIN_LIMIT:
                    os.remove(filename)
                    fwglobals.log.info("vpp_coredump_limit_cores:Remove core: %s" % (filename))


    def run(self):
        fwglobals.log.info("VPP coredump process: Thread start")
        FW_VPP_COREDUMP_LOCK.acquire()
        try:
            for corefile in self.corefiles:
                self.__vpp_coredump_compress(corefile)
            self.__vpp_coredump_limit_cores()
        except Exception as e:
            fwglobals.log.error("vpp coredump process Thread : Exception - %s" % str(e))
        finally:
            FW_VPP_COREDUMP_LOCK.release()
        fwglobals.log.info("VPP coredump process: Thread end")


def vpp_coredump_in_progress(filename):

    try:
        # Check if file can be write opened - to skip in progress cores
        file = open(filename, 'ab', buffering=0)
        file.close()
    except IOError as e:
        if e.errno == errno.EBUSY:
            fwglobals.log.info("vpp_coredump_compress: Likely VPP coredump in progress - %s %s"
                % (filename, os.strerror(e.errno)))
            return (True, None)
        else:
            fwglobals.log.error("vpp_coredump_compress: IO Error - %s %s"
                % (filename, os.strerror(e.errno)))
            return (False, None)
    return (False, filename)


def vpp_coredump_process():
    """
    It launches thread to compress and ratelimit VPP corefiles. Thread is not launched if already
    one is in progress or if no coredump is seen. If VPP coredump is in progress, pending flag is
    returned with True as a signal to try again
    """

    if FW_VPP_COREDUMP_LOCK.locked():
        fwglobals.log.trace("vpp_coredump_process: FW VPP Coredump process thread is in progress ")
        return True

    pending_count = 0
    corefiles = []
    try:
        files = glob.glob((FW_VPP_COREDUMP_LOCATION + FW_VPP_COREDUMP_START_STR + "*"))
        filenames = sorted(files, key=lambda t: os.stat(t).st_ctime)
        for filename in filenames:
            file = os.path.basename(filename)
            if filename.endswith(FW_VPP_COREDUMP_END_STR):
                fwglobals.log.info("vpp_coredump_process: core found: %s " % filename)
                pending, filename = vpp_coredump_in_progress(filename)
                if pending:
                    pending_count += 1
                elif filename:
                    corefiles.append(filename)
            else:
                continue
        if corefiles:
            core_process_thread = FwVppCoredumpProcess(corefiles)
            core_process_thread.start()
    except Exception as e:
        fwglobals.log.error("vpp coredump process : Exception - %s" % str(e))
    return True if pending_count > 0 else False


def vpp_coredump_copy_cores(dest_folder, copy_count):

    # Sorting enables selecting recent cores for copy
    files = glob.glob((FW_VPP_COREDUMP_LOCATION + FW_VPP_COREDUMP_START_STR + "*"))
    filenames = sorted(files, key=lambda t: -os.stat(t).st_ctime)
    count = 0
    for filename in filenames:
        if tarfile.is_tarfile(filename):
            shutil.copy2(filename, dest_folder)
            count = count +1
            if count == copy_count:
                break


def vpp_coredump_sys_setup():

    sys_cmd = 'sysctl -w kernel.core_pattern=/var/crash/core-%e-%p-%i-%s-%t-dump > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("vpp_coredump_sys_setup: command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.info("vpp_coredump_sys_setup: command successfully executed: %s" % (sys_cmd))

    sys_cmd = 'sysctl -w fs.suid_dumpable=2 > /dev/null'
    rc = os.system(sys_cmd)
    if rc:
        fwglobals.log.error("vpp_coredump_sys_setup: command failed : %s" % (sys_cmd))
    else:
        fwglobals.log.info("vpp_coredump_sys_setup: command successfully executed: %s" % (sys_cmd))


def vpp_coredump_setup_startup_conf(vpp_config_filename, enable):

    from tools.common.fw_vpp_startupconf import FwStartupConf
    startup_conf = FwStartupConf(vpp_config_filename)
    config = startup_conf.get_root_element()
    updated = 0
    coredump_full = 'full-coredump'
    coredump_size = 'coredump-size unlimited'
    if enable:
        if startup_conf.get_element(config['unix'], coredump_full) is None:
            coredump_full_config = startup_conf.create_element(coredump_full)
            config['unix'].append(coredump_full_config)
            updated = 1
        if startup_conf.get_element(config['unix'], coredump_size) is None:
            coredump_size_config = startup_conf.create_element(coredump_size)
            config['unix'].append(coredump_size_config)
            updated = 1
    else:
        coredump_full_config = startup_conf.get_element(config['unix'], coredump_full)
        if coredump_full_config:
            startup_conf.remove_element(config['unix'], coredump_full_config)
            updated = 1
        coredump_size_config = startup_conf.get_element(config['unix'], coredump_size)
        if coredump_size_config:
            startup_conf.remove_element(config['unix'], coredump_size_config)
            updated = 1
    if updated:
        startup_conf.dump(config, vpp_config_filename)
        if enable:
            fwglobals.log.info("vpp_coredump_setup_startup_conf: setup coredump params")
        else:
            fwglobals.log.info("vpp_coredump_setup_startup_conf: remove coredump params")
