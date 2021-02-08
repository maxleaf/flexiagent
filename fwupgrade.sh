#! /bin/bash

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

# Constants
AGENT_SERVICE_FILE='/etc/systemd/system/multi-user.target.wants/flexiwan-router.service'
AGENT_SERVICE='flexiwan-router'
SW_REPOSITORY='deb.flexiwan.com'
AGENT_CHECK_TIMEOUT=120

# Constants passed to the script by fwagent
TARGET_VERSION="$1"
VERSIONS_FILE="$2"
UPGRADE_FAILURE_FILE="$3"
AGENT_LOG_FILE="$4"

# Globals
prev_ver=''

log() {
    echo `date +'%b %e %R:%S'`" $HOSTNAME: fwagent:" "$@" >> "$AGENT_LOG_FILE" 2>&1
}

handle_upgrade_failure() {
    log 'Software upgrade failed'

    # Revert back to previous version if required
    if [ "$1" == 'revert' ]; then
        log 'Reverting to previous version ('"$prev_ver"')...'
        res=$(apt-get -y install --allow-downgrades "$AGENT_SERVICE"="$prev_ver")
        ret=${PIPESTATUS[0]}
        log $res

        if [ ${ret} != 0 ]; then
            log 'Failed to revert to previous version. Restarting fwagent'
            # Agent must be restarted if revert fails, or otherwise
            # it will remain stopped.
            systemctl restart "$AGENT_SERVICE"
        fi

        log 'handle_upgrade_failure: exit 1'
        exit 1
    fi

    # Create a file that marks the installation has failed
    touch "$UPGRADE_FAILURE_FILE"

    # Reconnect to MGMT
    res=$(fwagent start)
    if [ ${PIPESTATUS[0]} != 0 ]; then
        log $res
        log 'Failed to to connect to management'
    fi
    exit 1
}

get_prev_version() {
    if [ ! -f "$VERSIONS_FILE" ]; then
        log 'Device version file' "$VERSIONS_FILE" 'not found'
        return 1
    fi

    ver_entry=`grep device "$VERSIONS_FILE"`
    if [ -z "$ver_entry" ]; then
        log 'Device version not found in' "$VERSIONS_FILE"
        return 1
    fi

    prev_ver=`echo "$ver_entry" | awk '{split($0, res, " "); print res[2]}'`
}

update_service_conf_file() {
    if [ ! -f "$AGENT_SERVICE_FILE" ]; then
        log 'Service configuration file' "$AGENT_SERVICE_FILE" 'not found'
        return 1
    fi

    # Don't add the configuration if it already exists
    kill_mode_conf=`grep KillMode=process "$AGENT_SERVICE_FILE"`
    if [ -z "$kill_mode_conf" ]; then
        echo -e "\n[Service]\nKillMode=process" >> "$AGENT_SERVICE_FILE"
        systemctl daemon-reload
    fi
}

check_connection_to_sw_repo() {
    ping -c 1 deb.flexiwan.com >> /dev/null 2>&1
    if [ ${PIPESTATUS[0]} != 0 ]; then
        return 1
    fi
    return 0
}

# Upgrade process
log 'Starting software upgrade process...'

# Remove the file that represents upgrade failure. This file
# is created by either this script (if the failure is during the
# software upgrade process), or by the agent, if post-installation
# checks fail
rm "$UPGRADE_FAILURE_FILE" >> /dev/null 2>&1

# Save previous version for revert in case the upgrade process fails
get_prev_version
if [ -z "$prev_ver" ]; then
    log 'Failed to extract previous version from' "$VERSIONS_FILE"
    handle_upgrade_failure
fi

# Quit upgrade process if device is already running the latest version
dpkg --compare-versions "$TARGET_VERSION" le "$prev_ver"
if [ $? == 0 ]; then
    log 'Device already running latest version. Quiting upgrade process'
    exit 0
fi

# Stop agent connection loop to the MGMT, to make sure the
# agent does not prcoess messages during the upgrade process.
log 'Closing connection to MGMT...'
res=$(fwagent stop -r)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    log 'Failed to stop agent connection to management'
    handle_upgrade_failure
fi

log 'Installing new software...'

# Check connection to the software package repository.
# We have to check excplicitly since the 'apt-get update'
# command returns success status code even if the connection fails.
check_connection_to_sw_repo
if [ ${PIPESTATUS[0]} != 0 ]; then
    log 'Failed to connect to software repository ' "$SW_REPOSITORY"
    handle_upgrade_failure
fi

# Update debian repositories
res=$(apt-get update)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    log 'Failed to update debian repositores'
    handle_upgrade_failure
fi

# Upgrade device package. From this stage on, we should
# pass 'revert' to handle_upgrade_failure() upon failure

# Set "KillMode" option in the service file, to make sure systemd
# doesn't kill the upgrade process when the process is stopped
update_service_conf_file
if [ ${PIPESTATUS[0]} != 0 ]; then
    log 'Failed to update service configuration file'
    handle_upgrade_failure
fi

res=$(apt-get -o Dpkg::Options::="--force-confold" install -y "$AGENT_SERVICE")
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    handle_upgrade_failure 'revert'
fi

# Reopen the connection loop in case it is closed
res=$(fwagent start)
if [ ${PIPESTATUS[0]} != 0 ]; then
    log $res
    log 'Failed to to reconnect to management'
fi

# Wait to see if service is up and connected to the MGMT
log 'Finished installing new software. waiting for agent check ('"$AGENT_CHECK_TIMEOUT"' sec)'
sleep "$AGENT_CHECK_TIMEOUT"

if [ -f "$UPGRADE_FAILURE_FILE" ]; then
    log 'Agent checks failed'
    handle_upgrade_failure 'revert'
fi

log 'Software upgrade process finished successfully'
exit 0
