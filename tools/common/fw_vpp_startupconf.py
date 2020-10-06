################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2020  flexiWAN Ltd.
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
import shutil
import json
import re
import sys

"""
This class was created for the startupconf parserer/dumper. It mimics a tuple of two elements: a key,
and a L type list as a value Each L type list includes a list of T tuples, and so on, recursively.
It was created so we can use strings as keys, not just indices.
This was achieved by overriding [] with __setitem__ an __getitem__.
Trying to create a tuple with more or less then 2 elements will raise an exception.
"""
class T(list):
	T_ELEM_KEY = 0
	T_ELEM_VALUE = 1

	def __new__(self, titems):
		lst1 = titems
		self.list_len = len(lst1)
		if self.list_len != 2:
			raise TypeError,"ERROR: Type T must contain 2 elements: key and value, but includes %d element(s)" %(self.list_len)
			return None
		return list.__new__(T, (titems))

	def __getitem__(self, key):
		if isinstance(key, int) and key>=0 and key<2:
			return super(T, self).__getitem__(key)
		else:
			if super(T,self).__getitem__(self.T_ELEM_KEY) == key:
				return super(T,self).__getitem__(self.T_ELEM_VALUE)
			else:
				return None

	def __setitem__(self, key, value):
		if isinstance(key, int) and key>=0 and key<2:
			super(T,self).__setitem__(key,value)
		else:
			if super(T,self).__getitem__(self.T_ELEM_KEY) == key:
				super(T,self).__setitem__(self.T_ELEM_VALUE,value)

	"""
	API
	overriding append for the tuple. The 2nd element (index 1) in the tuple is an L-list.
	So we can use this knowledge to easily add elements to the list without using the
	key of the tuple. For example, instead of e['key'].append(value), we can simply use
	e.append(value)
	"""
	def append(self, value):
		if str(type(self[1])) == "<class 'fw_vpp_startupconf.L'>":
			self[1].append(value)

	def __str__(self):
		s = '(' + str(super(T,self).__getitem__(self.T_ELEM_KEY)) + ", " + str(super(T,self).__getitem__(self.T_ELEM_VALUE)) + ')'
		return s

"""
This class was created for the startupconf parserer/dumper. It mimics a list, that holds T elements.
It was created so we can access elements by their string key, and not just by their indices. 
To do that, we implemented __getitem__ and __setitem__, overriding the [] operator.
"""
class L(list):
	L_ELEM_KEY = 0
	L_ELEM_VALUE = 1

	def __new__(self, *litems):
		return list.__new__(L, (litems))

	def __getitem__(self, key):
		if isinstance(key, int):
			return super(L, self).__getitem__(key)
		elif not isinstance(key, int):
			"""
			This is because we know an element in the list is a tuple (key, []).
			It breaks the generalization of L, but we wrote it specifically for
			the startupconf module, so we can do that.
			"""
			for element in self:
				if str(type(element)) == "<class 'fw_vpp_startupconf.T'>":
					if element[self.L_ELEM_KEY] == key:
						return element[self.L_ELEM_VALUE]
			return None

	def __str__(self):
		ln = len(self)
		s = '['
		for i in range(ln):
			s = s + str(self[i])
			if i < ln - 1:
				s = s + ', '
		s = s + ']'
		return s

class FwStartupConf:
	"""
	This is the main class of the startupconf parser/dumper.
	It loads the startup.conf file, and parse it line by line. Based on the content of each line,
	it builds its internal database. The DB is an L-list of T-tuples. Each T-tuple has a key, and a value
	which is an L-list. It can be an empty list, in which case the key part of the tuple is the value (for
	example ('socket-mem 2048,2048', [])), or a non empty list, in which case the key is the key to the L-list.
	This goes on recursively (for example ('dpdk', []) is a key to a list, and one of the element of the list,
	a tuple with key 'dev 0000:02:00.1', has a value of a non-empty list as well).
	One can look at the created DB in the following way:
	[
		T('key1', L[])
		T('key2', L[])
		T('key1', L[
					T('sub-key1', L[])
					T('sub-key2', L[])
					T('sub-key3', L[
									T('subsub-key1', L[])
									T('subsub-key2', L[])
									T('subsub-key3', L[])
									])
					T('sub-key4', L[]
					]
		T('key4', L[])
	]
	
	User should create an instance of that class, and then call the load() API, with the file name. The return
	value of load is a populated L-type list. Several APIs are created to help traverse the DB, add elements and
	remove them, etc.

	When editing to DB is finished, user should call the dump API to dump the DB back to a file.
	"""

	ADD_LIST                   = 1
	ADD_LINE                   = 2
	ADD_SINGLE_LINE_LIST	   = 3
	CLOSE_LIST                 = 4

	def __init__(self):
		# The DB is a list of tuples. This is the main list.
		self.main_list  = L([])
		# use to follow the tree when we are dealing with a list inside a list (and so on)
		self.listOfList = [self.main_list]
		self.path       = ''  #For Debugging, gives path of keys (e.g. 'cpu' or 'dpdk'/'dev default')
		self.levels     = 0   #For Debugging, gives depth of keys (e.g. 1 in case of 'cpu'; 2 in case of'dpdk'/'dev default')
		self.in_fp      = ''
		self.out_fp     = sys.stdout
		self.key        = ''
		self.value      = ''
		self.curr_list  = self.main_list

	def _create_list(self, lst):
		"""
		This function creates a list, as the result of a line in the startupconf file that either look like this:
		key {
		or
		key { val
		
		:param lst: list to populate
		"""
		if self.value != '':
			"""
			case of key { val. In this case val is the first element in the list of its owner
			tuple. So we create tuple and an inner tuple which is the first element in the list.
			""" 
			sub_tup = self.create_element(self.value)
			tup = self.create_element(self.key)
			tup.append(sub_tup)
		else:
			"""
			case of key { . We create regular tuple with empty list as value.
			"""
			tup = self.create_element(self.key)
		lst.append(tup)
		self.path = self.path+ '/' + self.key
		self.levels +=1
		self.listOfList.append(tup[1])
		self.curr_list = self.listOfList[len(self.listOfList)-1]
		self.key = self.value = ''

	def _add_single_line_list(self):
		"""
		This function creates a single-value list, as the result of a line in the startupconf file that looks like:
		key { val }
		"""
		sub_tup = self.create_element(self.value)
		tup = self.create_element(self.key)
		tup.append(sub_tup)
		self.curr_list.append(tup)
		self.key = self.value = ''

	def _close_list(self):
		"""
		This function closes a list. List is closed when the } sign appear in a single line in startupconf file
		"""
		if len(self.listOfList) > 1:
			del self.listOfList[-1]
			self.curr_list = self.listOfList[len(self.listOfList)-1]
		else:
			self.listOfList = self.main_list
			self.curr_list = None

		steps = self.path.split('/')
		del steps[-1]
		self.path = '/'.join(steps)
		self.levels -= 1

	def _add_line(self):
		"""
		This function adds a single line to the database. In facts, it adds a tuple with a key and an empty list.
		The function is triggered by a single line in the startupconf file, such as 'num-rx-queues 3'
		"""
		tup = self.create_element(self.key)
		self.curr_list.append(tup)
		self.key = self.value = ''

	def _parse_line(self, line):
		"""
		This function parses a line read from the startup.conf file. According to the content of the line,
		the appropriate return value is returned to trigger the appropriate function to update the DB.

		:param line:  The line to parse
		"""
		line = line.strip()
		if '{' in line:
			if line.endswith('}'):
				"""
				Case of single line list as a 2nd value in a tuple: key { value }
				"""
				self.key = line.split('{')[0].strip()
				self.value = line.split('{')[1]
				self.value = self.value[0:len(self.value)-1].strip()
				return self.ADD_SINGLE_LINE_LIST
			elif not line.endswith('}') and line[-1].isalpha():
				"""
				case of list starts in the same line of key : key { value
				"""
				self.key = line.split('{')[0].strip()
				self.value = line.split('{')[1].strip()
				return self.ADD_LIST
			else:
				"""
				Case of multi line list as a value of a the 2nd element of a tuple: 
				dev 0000:02:00.1 {             
				name eth0   
				num-rx-queues 2               
				}
				"""
				self.key = line.split('{')[0].strip()
				self.value = ''
				return self.ADD_LIST
				
		elif line.strip('{}') == line:
			"""
			a simple line to add to the list: num-mbufs 128000
			"""
			self.key = line.strip()
			self.value = ''
			return self.ADD_LINE
		elif line == '}':
			return self.CLOSE_LIST

	def load(self, file_name):
		"""
		API.
		This function reads the startup.conf file, and load it to the DB.

		:param file_name:    The configuration file to read. Usually this will be startup.conf
		"""
		with open(file_name, "r") as self.in_fp:
			for new_line in self.in_fp:
				line = new_line.strip()
				if len(line) == 0 or line.startswith('#'):
					continue
				result = self._parse_line(line)

				if result == self.ADD_LIST:
					self._create_list(self.curr_list)
					continue

				elif result == self.ADD_LINE:
					self._add_line()
					continue

				elif result == self.ADD_SINGLE_LINE_LIST:
					self._add_single_line_list()
					continue

				elif result == self.CLOSE_LIST:
					self._close_list()
					continue
		return self.main_list

	def __str__(self):
		return json.dumps(self.listOfList[0],sort_keys=True,indent=2, separators=("",""))
		#return repr(self.listOfList[0])

	def create_element(self, str):
		"""
		API.
		This is a helper function. It creates a T tuple from an str which is the key in the tuple.
		So when user wish to create a new tuple, s/he will call this function with the requested key,
		and it will return a T(['key', L([])]).
		"""
		return T([str, L([])])

	def remove_element(self,lst,key):
		"""
		API.
		This function removes a tuple with the key 'key' from the owning list. If the tuple had a non-empty list
		as a value, it will be deleted as well.

		:param lst:    The list from which to remove the tuple
		:param key:    The key of the tuple to be removed
		"""
		for element in lst:
			if element[0] == key:
				lst.remove(element)

	def get_element(self, lst, search_str):
		""" 
		API.
		This function gets the key from a tuple. Should be used when the tuple represents a string line in the
		correspoding startup.conf file. Strings in startup.conf file are translated to tuples with key and empty
		list. This means that the key is the actual value. The function will return the tuple which its key starts
		with the string given to be searched. For example: get_element(db['cpu'], 'corelist-work') will return a
		string "corelist-workers 2-3,18-19", as this is the first line inside 'cpu' section that has the search string
		'corelist-work' in it.

		:param lst:         The list to search the value from
		:param search_str:  The search string to use to mach for the tuple's key
		"""
		for element in lst:
			if element[0] is not None and element[0].startswith(search_str):
				return element[0]
		return None

	def add_element_after(self, lst, element, new_element):
		"""
		API.
		When order of elements in list is important, this function adds a new element after an existing element.

		:param lst:         The list to add the new element to
		:param element:     The element that new_element should be inserted after
		:param new_element: The new element to add
		"""
		try:
			idx = lst.index(element)
		except ValueError:
			return False
		else:
			lst.insert(idx+1, new_element)
			return True

	def get_tuple_from_key(self, lst, key):
		"""
		API.
		Gets a Tuple from a key string. This function go over the given list, and looks for a tuple with the key
		'key'. If found, it returns the whole tuple.

		:param lst:    The list to traverse on
		:param key:    THe tuple's key to look for
		"""
		for element in lst:
			if element[0].strip() == key.strip():
				return element
		return None

	def get_main_list(self):
		"""
		API.
		Returns the head of the DB
		"""
		return self.main_list

	def dump(self, db, file_name):
		"""
		API.
		This function takes the DB and dumps it to the file_name, ususally startup.conf

		:param db:        The database to dump to the file
		:param file_name: The file name to dump the DB into
		"""
		with open (file_name, 'w') as self.out_fp:
			indent = 0
			self._dump_list(db,indent)

			
	def _dump_list(self, value, indent):
		"""
		This function dumps a list, recursively, into the startup.conf file. For each element in the given value,
		it checks the type. If the type is a list, it calls itself again, creating a list inside a list. If
		the type is tuple, it calls the tuple dump function.

		:param value:   the value to dump
		:param indent:  the indentation of the value inside the startup.conf file. 
		"""
		for element in value:
			if str(type(element)) == "<class 'fw_vpp_startupconf.T'>":
				self._dump_tuple(element, indent+1)
			elif str(type(element)) == "<class 'fw_vpp_startupconf.L'>":
				self._dump_list(element, indent+1)
			else:
				self._dump_line("dump_list: ERROR %s" %(str(type(element))), indent)

	def _dump_tuple(self, value, indent):
		"""
		This function dumps a tuple, recursively, into the startup.conf file. For each element in the given value,
		it checks the type. If the type is a list, it calls the list dump function. If this is a tuple, it dumps
		its value to the startup.conf
		
		:param value:   the value to dump
		:param indent:  the indentation of the value inside the startup.conf file. 
		"""
		string = value[0]
		string = string.strip('\'')
		# This is a case for main category with empty list of values.
		if (str(type(value[1]))) == "<class 'fw_vpp_startupconf.L'>" and len(value[1])==0 and indent == 1:
			# This is a case of key in main list with empty list of values.
			string = string + " {\n"
			self._dump_line(string, indent)
			self._dump_line('}\n\n',indent)
		elif (str(type(value[1]))) == "<class 'fw_vpp_startupconf.L'>" and len(value[1])>0:
			if len(value[1]) == 1 and indent > 1:
				#list[tuple[0]], value[1] is a list, so val is the 1st element of the first tuple in the list
				val = value[1][0][0] 
				string = string + " { " + val + " }\n"
				self._dump_line(string, indent)
			else:
				string = string + " {"
				self._dump_line(string + '\n', indent)
				self._dump_list(value[1], indent+1)
				self._dump_line("}\n\n", indent)
		else:
			if indent>0:
				self._dump_line(string + "\n", indent)
		return

	def _dump_line(self, value, indent):
		"""
		This function dumps a value (single line) to the startup.conf file.

		:param value:   the value to dump
		:param indent:  the indentation of the value inside the startup.conf file.
		"""
		self.out_fp.write("  " * indent + value)
