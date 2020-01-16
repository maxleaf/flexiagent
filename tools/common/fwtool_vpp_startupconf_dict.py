#! /usr/bin/python

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
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
import re
import ruamel.yaml
import shutil

#######################################################################
# Converts startup.conf from vpp format into yaml,
# while preserving comments, and loads it into dictionary.
#######################################################################
# Example input:
#    unix {
#       nodaemon
#       log /var/log/vpp/vpp.log
#       full-coredump
#       cli-listen /run/vpp/cli.sock
#       gid vpp
#    }
#
#    api-trace {
#    ## This stanza controls binary API tracing. Unless there is a very strong reason,
#    ## please leave this feature enabled.
#       on
#    }
#
#    api-segment {
#       gid vpp
#    }
#
#    #cpu {
#            ## Set logical CPU core where main thread runs, if main core is not set
#            ## VPP will use core 1 if available
#            # main-core 1
#    #}
#
#    dpdk {
#            ## Change default settings for all interfaces
#            dev default {
#                    ## Number of receive queues, enables RSS
#                    ## Default is 1
#                    # num-rx-queues 3
#            }
#
#            ## Whitelist specific interface by specifying PCI address
#            # dev 0000:02:00.0
#
#            ## Whitelist specific interface by specifying PCI address and in
#            ## addition specify custom parameters for this interface
#            # dev 0000:02:00.1 {
#            #       num-rx-queues 2
#            # }
#    }
#
#            ## Alternate syntax to choose plugin path
#            # plugin_path /home/bms/vpp/build-root/install-vpp-native/vpp/lib/vpp_plugins
#    nat { endpoint-dependent }
#
#######################################################################
# Example output:
#
#    unix:
#      - nodaemon
#      - log: /var/log/vpp/vpp.log
#      - full-coredump
#      - cli-listen: /run/vpp/cli.sock
#      - gid: vpp
#
#    api-trace:
#    ## This stanza controls binary API tracing. Unless there is a very strong reason,
#    ## please leave this feature enabled.
#      - on
#
#    api-segment:
#      - gid: vpp
#
#    socksvr:
#      - default
#
#    cpu:
#        ## Set logical CPU core where main thread runs, if main core is not set
#        ## VPP will use core 1 if available
#        # main-core 1
#
#    dpdk:
#        ## Change default settings for all interfaces
#        - dev default:
#            ## Number of receive queues, enables RSS
#            ## Default is 1
#            # num-rx-queues 3
#
#        ## Whitelist specific interface by specifying PCI address
#        # dev 0000:02:00.0
#
#        ## Whitelist specific interface by specifying PCI address and in
#        ## addition specify custom parameters for this interface
#        # dev 0000:02:00.1:
#        #    num-rx-queues 2
#        #
#
#        ## Alternate syntax to choose plugin path
#        # plugin_path /home/bms/vpp/build-root/install-vpp-native/vpp/lib/vpp_plugins
#
#    nat:  endpoint-dependent
#######################################################################
def load(config_filename):
    """Converts startup.conf from vpp format into yaml,
    while preserving comments, and loads it into dictionary.

    :param config_filename:       Configuration file.

    :returns: Configuration dictionary.
    """
    # Copy config file to temporary file,
    # as we have to preprocess it before feeding it to ruamel.yaml.
    yaml_filename = config_filename + '.yaml.in.tmp'
    shutil.copyfile(config_filename, yaml_filename)

    # Preprocess to convert vpp format into yaml format
    # -------------------------------------------------------
    # Replace tabs
    os.system("sed -i -E 's/\t/    /g' %s" % yaml_filename)
    # Remove '# ' at the line beginning to uncomment sections
    # in order to create empty dictionaries for them.
    # This is needed to force addition of the first new parameter
    # into commented section at the same place in file,
    # where the section was located before load & store operation.
    # Otherwise we might got sections - one the original the commented one,
    # and the other one is the new not commented with new parameters.
    os.system("sed -i -E 's/^([ ]{0,3})#[ ]*([^#]+)/\\1\\2/g' %s" % yaml_filename)
    # Add ':' before {} block to denote key-value pairs
    os.system("sed -i -E 's/([^:]) \{/\\1: \{/g' %s" % yaml_filename)
    # Remove '{' and '}' to prevent yaml.load confuse
    os.system("sed -i -E 's/\{|\}//g' %s" % yaml_filename)
    # Add '-' at the start of values to form lists.
    # Otherwise whole content of the {} block is read as string.
    # Note, we have do that after removal of '{' and '}',
    # so they will not be prefixed with '-'
    os.system("sed -i -E 's/^([ ]+)([^# ])/\\1- \\2/' %s" % yaml_filename)
    # Replace ' ' with ': ' in key-value pairs
    os.system("sed -i -E 's/^([ ]+)-([ ]+[^ ]+)([ ]+)([^ ]+)$/\\1-\\2: \\4/' %s" % yaml_filename)
    # Replace back ': ' with ' ' in 'dev: 0000:02:00.1' lines,
    # because 'dev' can't be key in dictionary, as multiple devices are allowed in file.
    os.system("sed -i -E 's/^([ ]+)-([ ]+[^ ]+)(:[ ]+)([^ \}]+)$/\\1-\\2 \\4/' %s" % yaml_filename)

    # Finally load configuration in yaml format from file into dictionary,
    # while preserving comments contained in the file.
    with open(yaml_filename, 'r') as f:
        ruamel_yaml = ruamel.yaml.YAML()
        config_dict = ruamel_yaml.load(f)
    return config_dict


#######################################################################
# Flushes dictionary with comments (created by ruamel.yaml)
# into vpp configuration file (startup.conf)
#######################################################################
# Example of input:
#    unix:
#    - nodaemon
#    - log: /var/log/vpp/vpp.log
#    - full-coredump
#    - cli-listen: /run/vpp/cli.sock
#    - gid: vpp
#
#
#    api-trace:
#    ## This stanza controls binary API tracing. Unless there is a very strong reason,
#    ## please leave this feature enabled.
#    - on
#
#
#    api-segment:
#    - gid: vpp
#
#
#    socksvr:
#    - default
#
#
#    cpu:
#        ## Set logical CPU core where main thread runs, if main core is not set
#        ## VPP will use core 1 if available
#        # main-core 1
#
#
#    dpdk:
#        ## Change default settings for all interfaces
#    - dev default:
#            ## Number of transmit queues, Default is equal
#            ## to number of worker threads or 1 if no workers treads
#            # num-tx-queues 3
#
#        ## Whitelist specific interface by specifying PCI address
#        # dev 0000:02:00.0
#      - num-rx-desc: 512
#      - num-tx-desc: 512
#
#        ## Whitelist specific interface by specifying PCI address and in
#        ## addition specify custom parameters for this interface
#        # dev 0000:02:00.1:
#        #    num-rx-queues 2
#        #
#
#
#    plugins:
#
#
#    nat: endpoint-dependent
#
#######################################################################
# Example of output:
#    unix {
#        nodaemon
#        log /var/log/vpp/vpp.log
#        full-coredump
#        cli-listen /run/vpp/cli.sock
#        gid vpp
#
#    }
#    api-trace {
#    ## This stanza controls binary API tracing. Unless there is a very strong reason,
#    ## please leave this feature enabled.
#        on

#    }
#    api-segment {
#        gid vpp
#    }
#    socksvr {
#        default
#    }
#    cpu {
#        ## Set logical CPU core where main thread runs, if main core is not set
#        ## VPP will use core 1 if available
#        # main-core 1
#    }
#    dpdk {
#        ## Change default settings for all interfaces
#        dev default {
#            ## Number of receive queues, enables RSS
#            ## Default is 1
#            # num-rx-queues 3
#
#        ## Whitelist specific interface by specifying PCI address
#        # dev 0000:02:00.0
#
#        ## Whitelist specific interface by specifying PCI address and in
#        ## addition specify custom parameters for this interface
#        # dev 0000:02:00.1 {
#        #    num-rx-queues 2
#        #
#
#        }
#        num-mbufs 2048
#
#    }
#    nat { endpoint-dependent }
#######################################################################
def dump(config_dict, config_filename='/etc/vpp/startup.conf', backup_filename='/etc/vpp/startup.conf.orig', debug=False):
    """Flushes dictionary with comments (created by ruamel.yaml)
    into vpp configuration file (startup.conf)

    :param config_dict:           Configuration dictionary.
    :param config_filename:       Configuration file.

    :returns: None.
    """
    # Backup original installation file and the last modified version
    if not os.path.isfile(backup_filename):
        shutil.copyfile(config_filename, backup_filename)
    dest_filename = config_filename + '.backup'
    shutil.copyfile(config_filename, dest_filename)

    # Dump configuration into yaml temporary file.
    yaml_filename = config_filename + '.yaml.out.tmp'
    f = open(yaml_filename, 'w')
    ruamel_yaml = ruamel.yaml.YAML()
    ruamel_yaml.dump(config_dict, f)
    f.close()

    # Preprocess it to convert yaml format into vpp format
    # ----------------------------------------------------
    dest_filename = config_filename + '.1.tmp'
    shutil.copyfile(yaml_filename, dest_filename)
    # Firstly form proper offset for list elements.
    # Note list elements are started with '-' and represent parameters
    # of startup.conf sections.
    # To avoid recursive code we handle hardcoded 2 levels of substructures :)
    os.system("sed -i -E 's/^-/    -/' %s" % dest_filename)
    os.system("sed -i -E 's/^  -/        -/' %s" % dest_filename)
    # 'nat: endpoint-dependent' -> 'nat { endpoint-dependent }'
    os.system("sed -i -E 's/^([^: ]+):[ ]*([^ ]+)$/\\1 \{ \\2 \}/' %s" % dest_filename)
    # Now we can remove list element notation '- '.
    # Do that after previous substitution to prevent wrong handling of '- num-mbufs: 4096' for example
    os.system("sed -i -E 's/^([ ]+)- (.+)$/\\1\\2/' %s" % dest_filename)
    # Replace key-value separating ':' with ' '
    os.system("sed -i -E 's/: ([^ ]+)/ \\1/' %s" % dest_filename)
    # Replace section opening ':' with '{'
    os.system("sed -i -E 's/:[ ]*$/ \{/' %s" % dest_filename)
    # Remove empty list leftovers that might be created by ruamel_yaml.dump: []
    os.system("sed -i -E '/^[ ]*\[[ ]*\][ ]*$/d' %s" % dest_filename)

    # Now we have to add section closing '}'
    # To my sorrow 'sed' can be used as multiline logic is needed.
    # So we do it in python way.
    # For every line with '{' add '}' before next line with lesser offset.
    out_lines   = []
    sec_offsets = []
    re_section_start = re.compile('([ ]*)[^#]+\{[ ]*$')
    re_offset        = re.compile('([ ]*)[^ ]+')
    re_comment       = re.compile('[ ]*#')
    re_empty_line    = re.compile('^$')

    with open(dest_filename, 'r') as f:
        for line in f.readlines():
            # Firstly take empty lines as is.
            # The commented lines can be used for offset calculation as well,
            # As they are not consistent, so take them as is. Hope it will not causes problems
            if re_empty_line.match(line) or re_comment.match(line):
                out_lines.append(line)
                continue
            # Now find offset of the current line
            match = re_offset.match(line)
            if not match:
                raise Exception("no offset found in %s!" % final_filename)
            current_offset = match.group(1)
            # If current offset is less or equal to the offset of last saved section,
            # we have to insert section closure and pop up the saved offsets.
            if len(sec_offsets) > 0 and len(sec_offsets[-1]) >= len(current_offset):
                out_lines.append("%s}\n" % sec_offsets[-1])
                del sec_offsets[-1]
                out_lines.append(line)
            else:
                out_lines.append(line)
            # Now check if the current line is start of next section.
            # If it does, save its offset. Escape commented lines.
            match = re_section_start.match(line)
            if match:   # start of section
                sec_offsets.append(match.group(1))

        # Clean up not closed section at the end of file
        for offset in reversed(sec_offsets):
            out_lines.append("%s}\n" % offset)

    # Now deal with another pitfall:
    # the 'plugins' section should contain at least one parameter.
    # Otherwise vpp fails to bootup. All the rest of sections work OK to our luck.
    # Therefore if 'plugins' section is empty, find it in lines and comment out.
    if 'plugins' in config_dict and config_dict['plugins'] is None:
        section_started = False
        for (idx, line) in enumerate(out_lines):
            if re.match('^[\s]*plugins', line):
                del out_lines[idx]
                out_lines.insert(idx, '# plugins {\n')
                section_started = True
                continue
            if section_started and re.match('^[\s]{0,2}\}', line):
                del out_lines[idx]
                out_lines.insert(idx, '# }\n')
                break

    # Write lines back to the file
    dest_filename = config_filename + '.2.tmp'
    with open(dest_filename, 'w') as f:
        f.writelines(out_lines)

    # Remove somehow doubled empty lines :)
    final_filename = config_filename + '.tmp'
    os.system("cat -s %s > %s" % (dest_filename, final_filename))

    shutil.copyfile(final_filename, config_filename)

    # Clean temporary files
    if debug == False:
        os.system("\\rm -rf %s/*.tmp" % os.path.dirname(final_filename))
