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
import json
from sqlitedict import SqliteDict

class FwMultilink:
    """This is object that encapsulates data used by multi-link feature.
    """
    def __init__(self, db_file):
        self.db_filename = db_file
        # Map of label strings (aka names) into integers (aka id-s) used by VPP.
        self.labels = SqliteDict(db_file, autocommit=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def finalize(self):
        """Destructor method
        """
        self.labels.close()

    def clean(self):
        """Clean DB

        :returns: None.
        """
        self.labels.clear()

    def _add_dict_entry(self, dict_key, key, value):
        if dict_key not in self.labels:
            self.labels[dict_key] = '{}'

        json_dict = json.loads(self.labels[dict_key])
        json_dict[key] = value
        self.labels[dict_key] = json.dumps(json_dict)

    def _remove_dict_entry(self, dict_key, key):
        json_dict = json.loads(self.labels[dict_key])
        del json_dict[key]
        self.labels[dict_key] = json.dumps(json_dict)

    def _get_dict_entry(self, dict_key, key):
        json_dict = json.loads(self.labels[dict_key])
        return json_dict[key]

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
                old_value = self._get_dict_entry(name, 'refCounter')
                if remove:
                    self._add_dict_entry(name, 'refCounter', old_value - 1)
                else:
                    self._add_dict_entry(name, 'refCounter', old_value + 1)
            else:
                new_id = len(self.labels)
                if new_id > 254:
                    raise Exception("FwMultilink: 1-byte limit for label ID is reached, can't store label")

                self._add_dict_entry(name, 'id', new_id)
                self._add_dict_entry(name, 'refCounter', 1)
                new_id += 1

            id = self._get_dict_entry(name, 'id')
            ids.append(id)

        # Clean id-s with no refCounter
        if remove:
            for name in names:
                if name in self.labels:
                    ref_counter = self._get_dict_entry(name, 'refCounter')
                    if ref_counter == 0:
                        del self.labels[name]

        gc_after = len(self.labels)

        fwglobals.log.debug("get_label_ids_by_names: gc=%d, input:  %s, remove=%s" % \
                            (gc_before ,names, str(remove)))
        fwglobals.log.debug("get_label_ids_by_names: gc=%d, output: %s" % \
                            (gc_after, ','.join(map(str, ids))))
        return ids
