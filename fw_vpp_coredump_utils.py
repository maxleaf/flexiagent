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

import os
import glob
import tarfile
import errno
import fwglobals
import threading
import shutil
import datetime
import subprocess
import traceback

FW_VPP_COREDUMP_FOLDER = "/var/crash"
FW_VPP_COREDUMP_PERMISSIONS = 0o775
FW_VPP_COREDUMP_LOCATION = FW_VPP_COREDUMP_FOLDER + "/"
FW_VPP_COREDUMP_START_STR = "core-vpp"
FW_VPP_COREDUMP_END_STR = "-dump"
FW_MAX_CORE_RETAIN_LIMIT = 3
FW_VPP_COREDUMP_LOCK = threading.Lock()
FW_APT_REPO_FILE = "/etc/apt/sources.list.d/flexiwan*source.list"

FW_VPP_GDB_SO_INFO_START = "=============== Shared library info START =============="
FW_VPP_GDB_SO_INFO_END = "=============== Shared library info END =============="
FW_VPP_WITH_SYM_PACK_ALL_DEP_LIB = True #debug option : For VPP with symbols, include all dep lib
FW_VPP_GDB_DEFAULT_LOG_FILE = "gdb.log"
FW_VPP_BIN_PATH = "/usr/bin/vpp"

FW_VPP_CORE_GDB_SOLIB_INFO=\
        "file " + FW_VPP_BIN_PATH + "\n" +\
        "core-file %s\n" +\
        "set logging overwrite on\n"+\
        "set logging on\n"+\
        "echo " + FW_VPP_GDB_SO_INFO_START + "\\n\n"+\
        "info sharedlibrary\n"+\
        "echo " + FW_VPP_GDB_SO_INFO_END + "\\n\n"+\
        "echo \\n\n"

class FwVppCoredumpProcess(threading.Thread):

    def __init__(self, corefiles):
        threading.Thread.__init__(self)
        self.corefiles = corefiles


    @staticmethod
    def __generate_solib_dependency_info(vpp_coredump_file, work_dir):

        gdb_log_file = work_dir + FW_VPP_GDB_DEFAULT_LOG_FILE
        out = FW_VPP_CORE_GDB_SOLIB_INFO % (vpp_coredump_file)
        gdb_info_command_file = work_dir + "fw_vpp_info.gdb"
        with open(gdb_info_command_file, 'w') as gdb_bt_fetch:
            gdb_bt_fetch.write(out)

        gdb_command = ['gdb', '-nx', '-batch', '-x']
        gdb_command.append(gdb_info_command_file)
        with open(gdb_log_file, "w") as gdb_log:
            subprocess.run(gdb_command, stdout=gdb_log, stderr=gdb_log)
        os.remove(gdb_info_command_file)
        return gdb_log_file


    @staticmethod
    def __get_gdb_shared_libs(work_dir):

        gdb_log_file = work_dir + FW_VPP_GDB_DEFAULT_LOG_FILE
        dep_shared_libs = []
        shared_libs_detected = False
        with open(gdb_log_file, "r") as gdb_log:
            lines = gdb_log.read().splitlines()
            for line in lines:
                if shared_libs_detected:
                    line_string_list = list(line.split(' '))
                    line_string_list_length = len(line_string_list)
                    if line_string_list_length:
                        solib_name = line_string_list[line_string_list_length - 1]
                        if '.so' in solib_name:
                            dep_shared_libs.append(solib_name)
                if FW_VPP_GDB_SO_INFO_START in line:
                    shared_libs_detected = True
                if FW_VPP_GDB_SO_INFO_END in line:
                    break
        return dep_shared_libs


    @staticmethod
    def __get_dpkg_shared_libs(work_dir):

        dpkg_shared_libs = set()
        dpkg_list_filename = work_dir + 'flexiwan-router-pkg.list'
        command = ['dpkg-query', '--listfiles', 'flexiwan-router']
        with open(dpkg_list_filename, "w") as out_file:
            subprocess.run(command, stdout=out_file) #Can throw CalledProcessError
        with open(dpkg_list_filename, "r") as dpkg_log:
            lines = dpkg_log.read().splitlines()
            for line in lines:
                if '.so' in line:
                    dpkg_shared_libs.add(line)
        return dpkg_shared_libs

    @staticmethod
    def __vpp_has_debug_symbols(work_dir):
        vpp_file_info = work_dir + "vpp_fileinfo.txt"
        command = ['file', FW_VPP_BIN_PATH]
        with open(vpp_file_info, "w") as out_file:
            subprocess.run(command, stdout=out_file) #Can throw CalledProcessError
        with open(vpp_file_info, "r") as file_log:
            lines = file_log.read().splitlines()
            for line in lines:
                if 'with debug_info' in line:
                    return True
        return False


    @staticmethod
    def __vpp_coredump_compress(corefile):

        # Make core and tar to contain readable core timestamp
        filename_parse = corefile.split("-")
        epoch_ts = int(filename_parse[len(filename_parse) - 2])
        ts_str = datetime.datetime.fromtimestamp(epoch_ts).strftime('%Y%m%d_%H%M%S')

        # Create work directory and prepare target tar filename/directory
        tar_dir_name = "fw_coredump-" + ts_str + "-" + os.path.basename(corefile)
        work_dir_path = FW_VPP_COREDUMP_LOCATION + "TEMP-" + tar_dir_name + "/"
        os.makedirs(work_dir_path, exist_ok=True)
        out_tar_filename = FW_VPP_COREDUMP_LOCATION + tar_dir_name + ".tar.gz"
        temp_out_tar_filename = out_tar_filename + ".TEMP"
        tar_file = tarfile.open(temp_out_tar_filename, "w:gz", dereference=True)

        # Include version and apt-repo file to tar packing
        dest_file = work_dir_path + os.path.basename(fwglobals.g.VERSIONS_FILE)
        shutil.copy(fwglobals.g.VERSIONS_FILE, dest_file)
        for filepath in glob.glob(FW_APT_REPO_FILE):
            dest_file = work_dir_path + os.path.basename(filepath)
            shutil.copy(filepath, work_dir_path)
            break

        # Add text backtrace to work directory and gets shared lib info
        FwVppCoredumpProcess.__generate_solib_dependency_info(corefile, work_dir_path)

        # Find/Add diff of the system libraries to be packed as part of coredump packing
        dep_shared_libs = FwVppCoredumpProcess.__get_gdb_shared_libs(work_dir_path)
        dpkg_shared_libs = FwVppCoredumpProcess.__get_dpkg_shared_libs(work_dir_path)
        include_all_dep = FW_VPP_WITH_SYM_PACK_ALL_DEP_LIB and \
                            FwVppCoredumpProcess.__vpp_has_debug_symbols(work_dir_path)
        for lib_name in dep_shared_libs:
            if (not (lib_name in dpkg_shared_libs)) or include_all_dep:
                tar_path_name = tar_dir_name + "/" + lib_name
                tar_file.add(lib_name, arcname=tar_path_name)
        if include_all_dep:
            tar_path_name = tar_dir_name + "/" + FW_VPP_BIN_PATH
            tar_file.add(FW_VPP_BIN_PATH, arcname=tar_path_name)

        # Add the files in work directory to the tar packing
        work_dir_files = glob.glob(work_dir_path)
        for file in work_dir_files:
            tar_path_name = tar_dir_name + "/" + os.path.basename(file)
            tar_file.add(file, arcname=tar_path_name)

        # Add corefile to the tar packing
        corefile_path_name = tar_dir_name + "/" + os.path.basename(corefile)
        tar_file.add(corefile, arcname=corefile_path_name)
        tar_file.close()

        shutil.rmtree(work_dir_path)
        os.rename(temp_out_tar_filename, out_tar_filename)
        os.remove(corefile)

        fwglobals.log.info("vpp_coredump_compress: compressed : %s" % (corefile))
        return out_tar_filename


    @staticmethod
    def __vpp_coredump_limit_cores():

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
        """
        Coredump packing thread's entry function. It compresses and packs required files
        as part of the package. It also limits the number of coredump package that shall be
        retained
        """
        fwglobals.log.info("VPP coredump process: Thread start")
        FW_VPP_COREDUMP_LOCK.acquire()
        try:
            for corefile in self.corefiles:
                self.__vpp_coredump_compress(corefile)
            self.__vpp_coredump_limit_cores()
        except Exception as e:
            fwglobals.log.error("vpp coredump process Thread : Exception: : - %s Traceback: %s" %
                    (str(e), str(traceback.format_exc())))
        finally:
            FW_VPP_COREDUMP_LOCK.release()
        fwglobals.log.info("VPP coredump process: Thread end")


def vpp_coredump_in_progress(filename):
    """
    Function that detects if the given coredump file is complete or is the
    coredump still in progress

    param: filename: Input coredump filename to be checked
    """
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
    """ Function that set required values to enable coredump in a Linux system
    """

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

    """ Function that enables VPP coredump by adding required variables
    in the startup config file

    :param vpp_config_filename: VPP startup file
    :param enable: Flag that enables or disable the coredump setting
    """
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
