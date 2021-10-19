#! /usr/bin/python3

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

from datetime import datetime

FWLOG_LEVEL_INFO  = 0x01
FWLOG_LEVEL_DEBUG = 0x0F
FWLOG_LEVEL_TRACE = 0xFF

class Fwlog:
    """This is logging class representation.

    :param level: Start logging from this severity level.
    """
    def __init__(self, level, name):
        """Constructor method
        """
        self.level = level
        self.to_syslog_enabled   = True
        self.to_terminal_enabled = True
        self.name                = name
    
    def __str__(self):
        return self.name

    def _build_log_line_prefix(self, add_date=False):
        # We prefix every log line with name of class that invoked the log print.
        #
        date = ''
        if add_date:
            # "Jul  6 04:14:30" - like in syslog except zero padding of day
            date = datetime.today().strftime('%b %d %H:%M:%S') + ': '
        return date

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
        if self.level >= FWLOG_LEVEL_INFO:
            self._log(log_message, to_terminal, to_syslog)

    def debug(self, log_message, to_terminal=True, to_syslog=True):
        """Print debug message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        if self.level >= FWLOG_LEVEL_DEBUG:
            self._log(log_message, to_terminal, to_syslog)

    def trace(self, log_message, to_terminal=True, to_syslog=True):
        """Print debug message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """
        if self.level >= FWLOG_LEVEL_TRACE:
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


class FwSyslog(Fwlog):
    def __init__(self, level=FWLOG_LEVEL_INFO, identification="fwagent"):
        """Constructor method
        """
        Fwlog.__init__(self, level=level, name="syslog(ident=fwagent)")
        syslog.openlog(ident=identification)

    def _log(self, log_message, to_terminal=True, to_syslog=True):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal.
        :param to_syslog:         Print to syslog.

        :returns: None.
        """

        # Prepend prefix (name of class that produced log line) and truncate the log line to 4K.
        # Note syslog discards lines beyond 8K by default, so take a caution if you modify this code!
        #
        log_message = self._build_log_line_prefix() + log_message
        if len(log_message) > 4096:
            log_message = log_message[0:4096] + ' <truncated>'

        if to_terminal and self.to_terminal_enabled:
            print(log_message)

        if to_syslog and self.to_syslog_enabled:
            syslog.syslog(log_message)


class FwLogFile(Fwlog):
    def __init__(self, filename, max_size=10000000, level=FWLOG_LEVEL_INFO):
        """Constructor method
        """
        Fwlog.__init__(self, level=level, name=filename)
        self.filepath, self.filename = os.path.split(filename)
        self.max_size = max_size  # 10 MB by default
        self.cur_size = 0

        if os.path.exists(filename):
            self.cur_size = os.path.getsize(filename)
        self.f = open(filename, 'a')

    def _rotate(self):
        self.f.close()
        main_filename = os.path.join(self.filepath, self.filename)
        backup_filename = os.path.join(self.filepath, self.filename + '.1')
        os.rename(main_filename, backup_filename)
        self.f = open(main_filename, 'w')
        self.cur_size = 0

    def _log(self, log_message, to_terminal=True, to_syslog=True):
        """Print log message.

        :param log_message:       Message contents.
        :param to_terminal:       Print to terminal - NOT IN USE for FwLogFile
        :param to_syslog:         Print to syslog

        :returns: None.
        """

        log_prefix  = self._build_log_line_prefix(add_date=True)
        log_message = log_message.replace('\r\n', '#012').replace('\n', '#012')  # Mimic syslog format
        log_message = log_prefix + log_message

        if to_syslog and self.to_syslog_enabled:

            # Split long line into chunks of 8K to make it compatible with various editors.
            #
            chunk_len = 8000
            total_len = len(log_message)

            if total_len <= chunk_len:
                self.f.write(log_message + '\n')
            else:
                msgs = [log_message[i:i+chunk_len] for i in range(0, total_len, chunk_len)]
                self.f.write(log_prefix + "--multiline-start--\n")
                for msg in msgs:
                    self.f.write(msg + '\n')
                self.f.write(log_prefix + "--multiline-end--\n")
            self.f.flush()

            self.cur_size += total_len
            if self.cur_size > self.max_size:
                self._rotate()


class FwObjectLogger:
    """Wraps the FwLog (by aggregation), while keeping object specific information,
    e.g. name of object class. This name is prepended to the log lines.
    For example if class FwCfgRequestHandler inherits from the FwObjectLogger,
    the FwCfgRequestHandler::log() will print "FwCfgRequestHandler: ..." lines
    into log.
    """
    def __init__(self, object_name, log=None):
        import fwglobals
        self.log = log if log else fwglobals.log if fwglobals.g_initialized else FwSyslog()
        self.prefix = f"{object_name}: "

    def excep(self, log_message, to_terminal=True, to_syslog=True):
        self.log.excep(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)

    def error(self, log_message, to_terminal=True, to_syslog=True):
        self.log.error(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)

    def warning(self, log_message, to_terminal=True, to_syslog=True):
        self.log.warning(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)

    def info(self, log_message, to_terminal=True, to_syslog=True):
        self.log.info(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)

    def debug(self, log_message, to_terminal=True, to_syslog=True):
        self.log.debug(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)

    def trace(self, log_message, to_terminal=True, to_syslog=True):
        self.log.trace(self.prefix + log_message, to_terminal=to_terminal, to_syslog=to_syslog)
