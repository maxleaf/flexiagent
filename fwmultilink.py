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

import fwglobals

class FwMultilink:
    """This is object that encapsulates data used by multi-link feature.
    """
    def __init__(self):
        self.labels = {}    # Map of label strings (aka names) into integers (aka id-s) used by VPP.

    def get_label_ids_by_names(self, names, remove=False):
        """Maps label names into label id-s.
        Label ID is two bytes integer.

        :param names:   list of strings that represent label names.
        :param remove:  True if label refCounter should be decremented and
                        label should be removed from database if no more
                        refCounter exist. False if refCounter should be incremented.

        :returns: list of id-s.
        """
        gc_before = len(self.labels)

        ids = []
        for name in names:
            if name in self.labels:
                if remove:
                    self.labels[name]['refCounter'] -= 1
                else:
                    self.labels[name]['refCounter'] += 1
            else:
                new_id  = len(self.labels)
                if new_id > 254:
                    raise Exception("FwMultilink: 1-byte limit for label ID is reached, can't store label")
                self.labels[name] = {}
                self.labels[name]['id']         = new_id
                self.labels[name]['refCounter'] = 1
                new_id  += 1

            id = self.labels[name]['id']
            ids.append(id)

        # Clean id-s with no refCounter
        if remove:
            for name in names:
                if name in self.labels and self.labels[name]['refCounter'] == 0:
                    del self.labels[name]

        gc_after = len(self.labels)

        fwglobals.log.debug("get_label_ids_by_names: gc=%d, input:  %s, remove=%s" % \
                            (gc_before ,names, str(remove)))
        fwglobals.log.debug("get_label_ids_by_names: gc=%d, output: %s" % \
                            (gc_after, ','.join(map(str, ids))))
        return ids
