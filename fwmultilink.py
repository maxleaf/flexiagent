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

class FwMultilink:
    """This is object that encapsulates data used by multi-link feature.
    """
    def __init__(self):
        self.labels = {}    # Map of label strings (aka names) into integers (aka id-s) used by VPP.

    def get_label_ids_by_names(self, names, is_dia=False, remove=False):
        """Maps label names into label id-s.
        Label ID is two bytes integer, where higher byte holds 'is_dia' flag
        and lower byte holds the label id in range [0..255].
        DIY stands for Direct Internet Access. It is used by VPP.

        :param names:   list of strings that represent label names.
        :param is_dia:  type of label, used by VPP (Direct Internet Access).
        :param remove:  True if label refCounter should be decremented and
                        label should be removed from database if no more
                        owners exist. False if refCounter should be incremented.

        :returns: list of id-s.
        """
        ids     = []
        new_id  = len(self.labels)
        for name in names:
            if name in self.labels:
                if remove:
                    self.labels[name]['owners'] -= 1
                else:
                    self.labels[name]['owners'] += 1
            else:
                if new_id > 0xFF:
                    raise Exception("FwMultilink: 1-byte limit for label ID is reached, can't store label")
                id = new_id | 0x100 if is_dia else new_id
                self.labels[name] = {}
                self.labels[name]['id'] = id
                self.labels[name]['owners'] = 1
                new_id  += 1
            ids.append(self.labels[name]['id'])

        # Clean id-s with no owners
        if remove:
            for name in names:
                if name in self.labels and self.labels[name]['owners'] == 0:
                    del self.labels[name]

        return ids
