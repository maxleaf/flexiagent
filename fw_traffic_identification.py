"""
DB for traffic identification store and lookup
"""
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

from sqlitedict import SqliteDict

import fwglobals

from fwobject import FwObject

class FwTrafficIdentifications(FwObject):

    """ Encapsulates functions associated with storing/removing/searching traffic identifiers.
    Each traffic identifier is a set of rules with match conditions and  carries traffic tags like
    category type, traffic class type and traffic importance
    """
    def __init__(self, db_file, logger=None):
        FwObject.__init__(self)

        # Traffic id to match rules
        self.traffic_id_map = SqliteDict(
            db_file, 'traffic_id', autocommit=True)
        # Category to traffic id(s)
        self.category_map = SqliteDict(db_file, 'category', autocommit=True)
        # Traffic class to traffic id(s)
        self.traffic_class_map = SqliteDict(
            db_file, 'traffic_class', autocommit=True)
        # Importance to traffic id(s)
        self.importance_map = SqliteDict(
            db_file, 'importance', autocommit=True)
        self.log = logger if logger else fwglobals.log

    def finalize(self):
        """
        Closes all traffic identifier DBs
        """
        self.traffic_id_map.close()
        self.category_map.close()
        self.traffic_class_map.close()
        self.importance_map.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.finalize()

    def clean(self):
        """
        Removes all entries in the traffic identifier DBs
        """
        self.traffic_id_map.clear()
        self.category_map.clear()
        self.traffic_class_map.clear()
        self.importance_map.clear()

    def __add_traffic_id(self, dict_store, key, traffic_id):

        values = dict_store.get(key, set())
        values.add(traffic_id)
        dict_store[key] = values

    def __remove_traffic_id(self, dict_store, key, traffic_id):
        values = dict_store.get(key, None)
        if values:
            values.remove(traffic_id)
            dict_store[key] = values

    def add_traffic_identification(self, traffic):
        """ Adds traffic identification to the traffic identifier database

        :param traffic: json/dict message carrying the identification details
        """
        traffic_id = traffic.get("id")
        category = traffic.get("category")
        traffic_class = traffic.get("serviceClass")
        importance = traffic.get("importance")
        self.traffic_id_map[traffic_id] = traffic
        self.log_info('Add traffic identification: ' + traffic_id)
        if category:
            self.__add_traffic_id(self.category_map, category, traffic_id)
        if traffic_class:
            self.__add_traffic_id(self.traffic_class_map, traffic_class, traffic_id)
        if importance:
            self.__add_traffic_id(self.importance_map, importance, traffic_id)

    def remove_traffic_identification(self, traffic):
        """ Removes traffic identification to the traffic identifier database

        :param traffic: json/dict message carrying the identification details
        """
        traffic_id = traffic.get("id")
        category = traffic.get("category")
        traffic_class = traffic.get("serviceClass")
        importance = traffic.get("importance")
        self.log_info('Remove traffic identification: ' + traffic_id)
        if traffic_id in self.traffic_id_map:
            del self.traffic_id_map[traffic_id]
        if category:
            self.__remove_traffic_id(self.category_map, category, traffic_id)
        if traffic_class:
            self.__remove_traffic_id(self.traffic_class_map, traffic_class, traffic_id)
        if importance:
            self.__remove_traffic_id(self.importance_map, importance, traffic_id)

    def get_traffic_rules(self, traffic_id, category, traffic_class, importance):
        """Looks up the traffic identification database based on the passed
        match conditions and returns the result of traffic identifiers.
        The result is a intersection set of all match conditions

        :param traffic_id: String identifier representing a traffic
        :param category: String name representing the traffic category type
        :param traffic_class: String name representing the traffic class
        :param importance: String name representing the traffic importance
        :return: Array of dict and each dict carries the traffic match condition
        """
        traffic_id_set = set()
        rules = []
        if traffic_id:
            if traffic_id in self.traffic_id_map:
                traffic_id_set.add(traffic_id)
        else:
            traffic_ids = []
            if category and category in self.category_map:
                traffic_ids.append(self.category_map.get(category))

            if traffic_class and traffic_class in self.traffic_class_map:
                traffic_ids.append(self.traffic_class_map.get(traffic_class))

            if importance and importance in self.importance_map:
                traffic_ids.append(self.importance_map.get(importance))

            if traffic_ids:
                traffic_id_set = set.intersection(*traffic_ids)

        for traffic_id in traffic_id_set:
            traffic = self.traffic_id_map.get(traffic_id)
            rules.extend(traffic.get('rules'))

        return rules
