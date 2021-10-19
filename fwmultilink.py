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

import fwglobals
import json
from sqlitedict import SqliteDict

from fwobject import FwObject

class FwMultilink(FwObject):
    """This is object that encapsulates data used by multi-link feature.
    """
    def __init__(self, db_file, fill_if_empty=True):
        FwObject.__init__(self)

        self.db_filename = db_file
        # The DB contains:
        # db['labels']     - map of label strings (aka names) into integers (aka id-s) used by VPP.
        # db['vacant_ids'] - pool of available id-s.

        self.db = SqliteDict(db_file, autocommit=True)
      
        if not fill_if_empty:
            return
            
        if not 'labels' in self.db:
            self.db['labels'] = {}
        if not 'vacant_ids' in self.db:
            self.db['vacant_ids'] = list(range(256))  # VPP uses u8 to keep ID, hence limitation of 0-255
        else:
            self.db['vacant_ids'] = sorted(self.db['vacant_ids'])  # Reduce chaos a bit :)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        self.db.close()

    def clean(self):
        """Clean DB
        """
        self.db['labels'] = {}
        self.db['vacant_ids'] = list(range(256))

    def dumps(self):
        """Prints content of database into string
        """
        db_keys = sorted(self.db.keys())                    # The key order might be affected by dictionary content, so sort it
        dump = [ { key: self.db[key] } for key in db_keys ] # We can't json.dumps(self.db) directly as it is SqlDict and not dict
        return json.dumps(dump, indent=2, sort_keys=True)

    def get_label_ids_by_names(self, names, remove=False):
        """Maps label names into label id-s.
        Label ID is two bytes integer.

        :param names:   list of strings that represent label names.
        :param remove:  True if label refCounter should be decremented and
                        label should be removed from database if no more
                        refCounter exist. False if refCounter should be incremented.

        :returns: list of id-s.
        """
        # Note we can't modify self.db subelements, as SqlDict can't detect
        # modifications in the object memory, so we have to replace whole
        # root element. That is why we use temporary copies of root elements.
        #
        labels     = self.db['labels']
        vacant_ids = self.db['vacant_ids']

        gc_before = len(labels)

        ids = []
        for name in names:
            if name in labels:
                if remove:
                    labels[name]['refCounter'] -= 1
                else:
                    labels[name]['refCounter'] += 1
                ids.append(labels[name]['id'])
            else:
                if remove:
                    raise Exception("FwMultilink: remove not existing label '%s'" % name)

                if len(vacant_ids) == 0:
                    self.db['labels']     = labels
                    self.db['vacant_ids'] = vacant_ids
                    raise Exception("FwMultilink: 1-byte limit for label ID is reached, can't store label '%s'" % name)

                new_id = vacant_ids.pop(0)
                labels[name] = {}
                labels[name]['id'] = new_id
                labels[name]['refCounter'] = 1
                ids.append(new_id)

        # Clean id-s with no refCounter
        if remove:
            for name in names:
                if name in labels:
                    if labels[name]['refCounter'] == 0:
                        vacant_ids.insert(0, labels[name]['id'])
                        del labels[name]

        self.db['labels']     = labels
        self.db['vacant_ids'] = vacant_ids

        gc_after = len(labels)

        self.log.debug("get_label_ids_by_names: input=%s, remove=%s, output=%s, gc: %d -> %d" % \
            (names, str(remove), ','.join(map(str, ids)), gc_before, gc_after))
        return ids
