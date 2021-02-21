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

import inspect
import os
import syslog
import sys

class Fwlog:
    """This is logging class representation.

    :param level: Start logging from this severity level.
    """
    FWLOG_LEVEL_INFO  = 0x01
    FWLOG_LEVEL_DEBUG = 0x0F
    FWLOG_LEVEL_TRACE = 0xFF

    def __init__(self, level=FWLOG_LEVEL_INFO):
        """Constructor method
        """
        self.level = level
        self.to_syslog_enabled   = True
        self.to_terminal_enabled = True
        syslog.openlog(ident="fwagent")

    def _log(self, log_message, to_terminal=True, to_syslog=True):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """

        # Find out name of class that invoked the log print and prepend it.
        #
        stack = inspect.stack()
        frame = stack[2]        # obj.f() -> fwlog.debug() -> _log
        obj = frame[0].f_locals.get('self')
        if obj:
            cls_name = obj.__class__.__name__
            log_message = cls_name + ': ' + log_message


        if to_terminal and self.to_terminal_enabled:
            print(log_message)

        if to_syslog and self.to_syslog_enabled:

            # syslog discards lines beyond 8K by default, so we fold them.
            # We use 8000 and not 8192 to leave space for syslog additions,
            # like pid, date, etc.
            #
            chunk_len = 8000
            msgs = [log_message[i:i+chunk_len] for i in range(0, len(log_message), chunk_len)]

            if len(msgs) == 1:
                syslog.syslog(log_message)
            else:
                syslog.syslog("--multiline-start--")
                for msg in msgs:
                    syslog.syslog(msg)
                syslog.syslog("--multiline-end--")

    def excep(self, log_message, to_terminal=True, to_syslog=True):
        """Print exception message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        self._log("excep: " + log_message, to_terminal, to_syslog)

    def error(self, log_message, to_terminal=True, to_syslog=True):
        """Print error message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        self._log("error: " + log_message, to_terminal, to_syslog)

    def warning(self, log_message, to_terminal=True, to_syslog=True):
        """Print warning message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        self._log("*** warning: " + log_message + " ***", to_terminal, to_syslog)

    def info(self, log_message, to_terminal=True, to_syslog=True):
        """Print info message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        if self.level >= self.FWLOG_LEVEL_INFO:
            self._log(log_message, to_terminal, to_syslog)

    def debug(self, log_message, to_terminal=True, to_syslog=True):
        """Print debug message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        if self.level >= self.FWLOG_LEVEL_DEBUG:
            self._log(log_message, to_terminal, to_syslog)

    def trace(self, log_message, to_terminal=True, to_syslog=True):
        """Print debug message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        if self.level >= self.FWLOG_LEVEL_TRACE:
            self._log(log_message, to_terminal, to_syslog)

    def set_level(self, level):
        """Set severity level to show messages that are above this level.

        :param level:             Severity level.

        :returns: None.
        """
        self.level = level

    def set_target(self, to_syslog=True, to_terminal=True):
        """Set default log output targets.

        :param to_syslog:         Output to syslog.
        :param to_terminal:       Output to terminal.

        :returns: None.
        """
        self.to_syslog_enabled   = to_syslog
        self.to_terminal_enabled = to_terminal

