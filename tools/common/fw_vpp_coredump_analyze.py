#! /usr/bin/python3

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
#
# Tested to work in python3.6

import argparse
import os
import shutil
import subprocess
import tarfile
import urllib.request
import yaml
import traceback

FW_PKG_URL = "https://deb.flexiwan.com/flexiWAN/pool/%s/f/flexiwan-router/"
FW_PKG_RTR = "flexiwan-router_%s.%s_amd64.deb"
FW_PKG_RTR_DBG = "flexiwan-router-dbg_%s.%s_amd64.deb"

FW_VPP_CORE_GDB_DEBUG_PATH = "/usr/lib/debug/"
FW_VPP_CORE_GDB_SETUP =\
        "set sysroot %s\n" +\
        "set debug-file-directory  %s\n" +\
        "file %s/usr/bin/vpp\n" +\
        "core-file %s\n"
FW_VPP_CORE_GDB_SCRIPT = "fw_vpp_setup.gdb"

FW_VPP_CORE_GDB_BT_INFO=\
        "set logging overwrite on\n"+\
        "set logging on\n"+\
        "set logging file %s\n" +\
        "echo ================== Backtrace  ====================\\n\n"+\
        "backtrace\n"+\
        "echo \\n\n"+\
        "echo ================== ThreadInfo ====================\\n\n"+\
        "info threads\n"+\
        "echo \\n\n"+\
        "echo ============= All thread backtraces ==============\\n\n"+\
        "thread apply all backtrace full\n"+\
        "echo \\n\n"


class FwVppCoredumpAnalyze():

    @staticmethod
    def __extract_corefile(compressed_corefile, cwd):
        corefile_tar = tarfile.open(compressed_corefile)
        file_list = corefile_tar.getnames()
        print("INFO: Extracting compressed corefile input: %s" % (compressed_corefile))
        corefile_tar.extractall()
        corefile_tar.close()
        work_dir = cwd + os.path.basename(compressed_corefile)[:-len(".tar.gz")] + "/"
        if os.path.isdir(work_dir):
            return work_dir, file_list
        raise Exception ("Invalid flexiwan Coredump %s" % work_dir)


    @staticmethod
    def __get_pkg_version(fw_version_file):
        # Fetch flexiwan version info from fwagent version file
        with open(fw_version_file, 'r') as version_data:
            version_info = yaml.safe_load(version_data)
            return version_info['device']


    @staticmethod
    def __get_fw_build_info(fw_repo_file):
        with open(fw_repo_file, 'r') as build_data:
            # Example: deb [ arch=amd64 ] https://deb.flexiwan.com/flexiWAN bionic main
            # Extract: 'bionic' and 'main' as os_release_type and repo_name
            build_info = build_data.readline()
            build_info_parse = build_info.split()
            return build_info_parse[5], build_info_parse[6]

    @staticmethod
    def __have_dependencies_been_packed(work_dir):
        '''
        Flexiwan coredump packager (fw_vpp_coredump_utils.py) includes all dependencies
        if the build carries debug symbols. Useful in taking contained coredumps when
        debugging using dev binaries and debug builds. If vpp binary exists, it indicates
        that the VPP dependencies have as well been included
        '''
        vpp_file_info = work_dir + "/usr/bin/vpp"
        if os.path.exists(vpp_file_info):
            return True
        return False


    @staticmethod
    def __fetch_build_pkg(fw_version, fw_repo, os_release, work_dir):
        url = FW_PKG_URL % (fw_repo)
        router_deb = FW_PKG_RTR % (fw_version, os_release)
        router_dbg_deb = FW_PKG_RTR_DBG % (fw_version, os_release)
        router_fetch_path = work_dir + "/" + router_deb
        router_dbg_fetch_path = work_dir + "/" + router_dbg_deb
        if os.path.exists(router_fetch_path):
            print("INFO: Router package exists in workspace - Skip download: %s" % router_deb)
        else:
            print("INFO: Downloading package: %s" % (url + router_deb))
            urllib.request.urlretrieve((url + router_deb), router_fetch_path)
        if os.path.exists(router_dbg_fetch_path):
            print("INFO: Symbol package exists in workspace - Skip download: %s" % router_dbg_deb)
        else:
            print("INFO: Downloading package: %s" % (url + router_dbg_deb))
            urllib.request.urlretrieve((url + router_dbg_deb), router_dbg_fetch_path)
        command = ['dpkg-deb', '-x']
        command.append(router_fetch_path)
        command.append(work_dir)
        print("INFO: Extracting package: %s" % (router_fetch_path))
        subprocess.run(command) #Can throw CalledProcessError
        command = ['dpkg-deb', '-x']
        command.append(router_dbg_fetch_path)
        command.append(work_dir)
        print("INFO: Extracting package: %s" % (router_dbg_fetch_path))
        subprocess.run(command) #Can throw CalledProcessError
        return


    @staticmethod
    def __setup_gdb_script(vpp_coredump_file, work_dir, cwd, has_debug_symbols, backtrace_only):

        if has_debug_symbols:
            debug_path = FW_VPP_CORE_GDB_DEBUG_PATH
        else:
            debug_path = work_dir + FW_VPP_CORE_GDB_DEBUG_PATH + ":" + FW_VPP_CORE_GDB_DEBUG_PATH
        out = FW_VPP_CORE_GDB_SETUP % (work_dir, debug_path, work_dir, (work_dir + vpp_coredump_file))

        if not backtrace_only:
            gdb_setup_file = work_dir + FW_VPP_CORE_GDB_SCRIPT
            with open(gdb_setup_file, 'w') as gdb_setup_script:
                gdb_setup_script.write(out)
            print("INFO: Coredump workspace setup successfully")
            print("\nTO START analysis, execute below command in Shell\n")
            print("gdb --command=%s%s" % (work_dir, FW_VPP_CORE_GDB_SCRIPT))
        else:
            gdb_log_file = cwd + vpp_coredump_file + ".backtrace"
            bt_out = out + (FW_VPP_CORE_GDB_BT_INFO % gdb_log_file)
            gdb_bt_command_file = work_dir + "fw_vpp_bt.gdb"
            with open(gdb_bt_command_file, 'w') as gdb_bt_fetch:
                gdb_bt_fetch.write(bt_out)

            gdb_command = ['gdb', '-nx', '-batch', '-x']
            gdb_command.append(gdb_bt_command_file)
            with open(gdb_log_file, "w") as gdb_log:
                subprocess.run(gdb_command, stdout=gdb_log, stderr=gdb_log)
            os.remove(gdb_bt_command_file)


    def setup_workspace(self, compressed_corefile, cwd, backtrace_only):
        """ Function that sets up workspace to perform gdb analysis.
        It downloads required packages and debug info and sets up workspace
        folder to analyze the core.

        :param compressed_corefile: input coredump package generated by flexiagent
        :param cwd: Current working directory
        :param backtrace_only: This option generates backtrace and cleans the workspace
        """
        try:
            work_dir, file_list = self.__extract_corefile(compressed_corefile, cwd)
            fw_version_file = None
            fw_repo_file = None
            vpp_coredump_file = None
            for filename in file_list:
                basename = os.path.basename(filename)
                if basename == ".versions.yaml":
                    fw_version_file = basename
                elif basename.endswith("source.list"):
                    fw_repo_file = basename
                elif basename.startswith("core-vpp"):
                    vpp_coredump_file = basename

            if not fw_version_file or not fw_repo_file or not vpp_coredump_file:
                print("ERROR: Not all required files found in coredump input file")
                exit(-1)
            has_debug_symbols = self.__have_dependencies_been_packed(work_dir)
            if not has_debug_symbols:
                fw_version = self.__get_pkg_version(work_dir + fw_version_file)
                os_release, fw_repo = self.__get_fw_build_info(work_dir + fw_repo_file)
                print("INFO: Version: %s  Repo: %s  OS_Release: %s" %\
                    (fw_version, fw_repo, os_release))
                self.__fetch_build_pkg(fw_version, fw_repo, os_release, work_dir)
            else:
                print("INFO: Given coredump package is generated from build with debug symbols")
            self.__setup_gdb_script(vpp_coredump_file, work_dir, cwd, has_debug_symbols, backtrace_only)
            if backtrace_only:
                shutil.rmtree(work_dir, ignore_errors=True)
                print("INFO: Cleaned up workspace directory %s" % (work_dir))
                print("\nGenerated backtrace is at: ./%s" % vpp_coredump_file + ".backtrace")

        except Exception as e:
            print ("ERROR: coredump workspace setup failed : - %s Traceback: %s" %
                    (str(e), str(traceback.format_exc())))
            return False
        return True


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Tool to setup coredump analysis workspace')
    parser.add_argument('-f', '--fw_corefile', default=None, required=True,
                        help="Provide compressed VPP coredump file generated by fwagent")

    #This option can be used to get the text backtrace only
    parser.add_argument('-d', '--dump_backtrace_only', action='store_true',
                        help="Dump a text backtrace of coredump")
    args = parser.parse_args()
    fw_corefile = args.fw_corefile
    cwd = os.getcwd() + "/"
    if not os.path.isfile(fw_corefile):
        fw_corefile = cwd + fw_corefile
        if not os.path.isfile(fw_corefile):
            print("ERROR: Input coredump file not found : %s" % args.fw_corefile)
            exit(-1)
    coredump_analysis = FwVppCoredumpAnalyze()
    coredump_analysis.setup_workspace(fw_corefile, cwd, args.dump_backtrace_only)
