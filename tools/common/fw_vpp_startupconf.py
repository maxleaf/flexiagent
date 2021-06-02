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
			raise Exception("ERROR: Type T must contain 2 elements: key and value, but includes %d element(s)" %(self.list_len))
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
		if re.search('fw_vpp_startupconf.L', str(type(self[1]))):
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
				if re.search('fw_vpp_startupconf.T', str(type(element))):
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

class FwStartupConfParsed:
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

	User should create an instance of that class, than call the get_root_element() API.
	This API returns populated L-type list. Several API-s are created to help
	user to traverse the DB, to add and remove element, etc.

	When editing to DB is finished, user should call the dump API to dump the DB back to a file.
	"""

	ADD_LIST                   = 1
	ADD_LINE                   = 2
	ADD_SINGLE_LINE_LIST	   = 3
	CLOSE_LIST                 = 4

	def __init__(self, filename=None):
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
		self.current_list  = self.main_list
		self.filename   = filename
		self.modified   = False

		if self.filename:
			self.main_list = self._load(self.filename)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		# The three arguments to `__exit__` describe the exception
		# caused the `with` statement execution to fail. If the `with`
		# statement finishes without an exception being raised, these
		# arguments will be `None`.
		if self.modified:
			self.dump()
		return

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
		self.current_list = self.listOfList[len(self.listOfList)-1]
		self.key = self.value = ''

	def _add_single_line_list(self):
		"""
		This function creates a single-value list, as the result of a line in the startupconf file that looks like:
		key { val }
		"""
		sub_tup = self.create_element(self.value)
		tup = self.create_element(self.key)
		tup.append(sub_tup)
		self.current_list.append(tup)
		self.key = self.value = ''

	def _close_list(self):
		"""
		This function closes a list. List is closed when the } sign appear in a single line in startupconf file
		"""
		if len(self.listOfList) > 1:
			del self.listOfList[-1]
			self.current_list = self.listOfList[len(self.listOfList)-1]
		else:
			self.listOfList = self.main_list
			self.current_list = None

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
		self.current_list.append(tup)
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

	def _load(self, filename):
		"""
		This function reads the startup.conf file, and load it to the DB.

		:param filename:    The configuration file to read. Usually this will be startup.conf
		"""
		with open(filename, "r") as self.in_fp:
			for new_line in self.in_fp:
				line = new_line.strip()
				if len(line) == 0 or line.startswith('#'):
					continue
				result = self._parse_line(line)

				if result == self.ADD_LIST:
					self._create_list(self.current_list)
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

	def get_root_element(self):
		"""
		API.
		Returns the head of the DB
		"""
		return self.main_list

	def get_element_value(self, lst, key):
		"""
		API.
		Returns the value of element.
		"""
		element = self.get_element(lst, key)
		if not element:
			return None
		tuple = self.get_tuple_from_key(lst, element)
		if not tuple:
			return None
		return tuple[0]

	def dump(self, element=None, filename=None):
		"""
		API.
		This function takes the DB and dumps it to the file_name, ususally startup.conf

		:param element:   The element to dump into the file.
		                  If not provided, the root element with whole tree will be dumped
		:param filename:  The file name to dump the DB into.
		                  If not provided, the one set on FwStartupCpnfParsed construction
						  will be used.
		"""
		if not filename:
			filename = self.filename
		if not element:
			element = self.get_root_element()
		with open (filename, 'w') as self.out_fp:
			indent = 0
			self._dump_list(element, indent)
			self.modified = False

	def _dump_list(self, value, indent):
		"""
		This function dumps a list, recursively, into the startup.conf file. For each element in the given value,
		it checks the type. If the type is a list, it calls itself again, creating a list inside a list. If
		the type is tuple, it calls the tuple dump function.

		:param value:   the value to dump
		:param indent:  the indentation of the value inside the startup.conf file.
		"""
		for element in value:
			if re.search('fw_vpp_startupconf.T', str(type(element))):
				self._dump_tuple(element, indent+1)
			elif re.search('fw_vpp_startupconf.L', str(type(element))):
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
		if re.search('fw_vpp_startupconf.L', str(type(value[1]))) and len(value[1])==0 and indent == 1:
			# This is a case of key in main list with empty list of values.
			string = string + " {\n"
			self._dump_line(string, indent)
			self._dump_line('}\n\n',indent)
		elif re.search('fw_vpp_startupconf.L', str(type(value[1]))) and len(value[1])>0:
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
		self._write_string(value, indent)

	def _write_string(self, value, indent):
		"""
		This function does the actual writing to the file pointer. We created it so we can easily switch 
		from a real file to stdout, viewing the results on screen.

		:param value:   the value to dump
		:param indent:  the indentation of the value inside the startup.conf file.
		"""
		self.out_fp.write("  " * indent + value)
		return

	def get_simple_param(self, path):
		'''Retrieves simple parameter by path.
		Simple parameter has format of "<name> <value>", e.g.
			dpdk {
				dev default { num-rx-queues 5 }
			}
		Here the <name> is "num-rx-queues", the value is "5".
		The 'path' is "dpdk.dev default.num-rx-queues".

		:returns: the value of the parameter as a string, or None if not found.
		'''
		param = path.split('.')[-1]
		path  = path.split('.')[:-1]

		element = self.get_root_element()
		for step in path:
			if element[step] == None:
				return None
			element = element[step]

		return self.get_element_value(element, param)


	def set_simple_param(self, path, val, commit=False):
		'''Sets value for the simple parameter identified by path.
		Simple parameter has format of "<name> <value>", e.g.
			dpdk {
				dev default { num-rx-queues 5 }
			}
		Here the <name> is "num-rx-queues", the value is "5".
		The 'path' is "dpdk.dev default.num-rx-queues".

		:param path:   The path to the most inner section that includes the parameter.
		               If any of sections in path does not exist, it will be created.
					   If parameter does not exists, it will be created too.
		:param val:    The value to be set for this parameter.
		               Can be of any type, that supports casting to string by str().
		:param commit: If True, the modification will be flushed into underlying
		               file immediately'.
		'''

		val = str(val)	# Enable integers and other as a parameter value :)

		param = path.split('.')[-1]
		path  = path.split('.')[:-1]

		element = self.get_root_element()
		for step in path:
			if element[step] == None:
				element.append(self.create_element(step))
			element = element[step]

		# If parameter exists, delete it before adding the new one, than add.
		#
		old_val = self.get_element_value(element, param)
		if old_val != None:
			self.remove_element(element, old_val)

		element.append(self.create_element('%s %s' % (param, val)))

		self.modified = True
		if commit:
			self.dump()


	def del_simple_param(self, path, commit=False):
		'''Deletes simple parameter identified by path.
		Simple parameter has format of "<name> <value>", e.g.
			dpdk {
				dev default { num-rx-queues 5 }
			}
		Here the <name> is "num-rx-queues", the value is "5".
		The 'path' is "dpdk.dev default.num-rx-queues".

		:param path:   The path to the most inner section that includes the parameter.
		               If the inner sections become empty as a result or parameter
					   deletion, they will be deleted as well.
		:param commit: If True, the modification will be flushed into underlying
		               file immediately'.
		'''
		def _clean_empty_sections(_element, _path):
			if len(_element[_path[0]]) == None:
				return
			if len(_element[_path[0]]) == 0:
				self.remove_element(_element, _path[0])
				return
			if len(_path) == 1:  # We reached leaf element
				return
			_clean_empty_sections(_element[_path[0]], path[1:])


		param = path.split('.')[-1]
		path  = path.split('.')[:-1]

		element = self.get_root_element()
		for step in path:
			if element[step] == None:
				return
			element = element[step]

		val = self.get_element_value(element, param)
		if val == None:
			return
		self.remove_element(element, val)

		# Now clean up - remove sub sections that became empty as a result of parameter deletion
		#
		_clean_empty_sections(self.get_root_element(), path)

		self.modified = True
		if commit:
			self.dump()



class FwStartupConf(FwStartupConfParsed):
	"""
	The wrapper of the /etc/vpp/startup.conf file that provides convenient API-s
	to modify parameters stored in this file.
	This class inherits from the FwStartupConfParsed while wrapping generic
	API-s for access file parameters with the one-liner functions that modify
	specific parameter.
	"""

	def get_cpu_workers(self):
		'''Retrieves number of worker threads based on value of the cpu.corelist-workers field
		'''
		corelist_workers_string = self.get_simple_param('cpu.corelist-workers')
		if not corelist_workers_string:
			return 0

		# Parse "corelist-workers 1-5" or "corelist-workers 2" string into list
		#
		corelist_workers_list = re.split('[-|\s]+', corelist_workers_string.strip())
		if len(corelist_workers_list) < 3:
			raise Exception("get_cpu_workers: not supported format: '%s'" % corelist_workers_string)
		if len(corelist_workers_list) == 3:
			return int(corelist_workers_list[2])
		return int(corelist_workers_list[3]) - int(corelist_workers_list[2]) + 1


	def set_cpu_workers(self, num_workers, num_interfaces=2, rx_queues=None, tx_queues=None, commit=False):
		'''Sets worker threads related parameters:
			- cpu.main-core
			- cpu.corelist-workers
			- buffers.buffers-per-numa
			- dpdk.dev default.num-rx-queues4
		Worker threads forward received packets.

		If num_workers is 0, deletes all these parameters,
		otherwise sets them as follows:
			- cpu.main-core = 0	 (main thread always runs on core #0, workers - on the rest)
			- cpu.corelist-workers = 1-<num_workers>
			- dpdk.dev default.num-rx-queues = <num_workers>
			- buffers.buffers-per-numa = see in code documentation

		:param num_workers:    number of worker threads to be configured
		:param num_interfaces: number of interfaces served by workers
		                       Default value is 2 -> 1 LAN and 1 WAN.
		:param rx_queues: 	   number of RX queues if network cards support RSS.
		                       Default value is 'num_workers'.
		:param tx_queues: 	   number of TX queues.
		                       Default value is 'num_workers'.
		'''
		# To simplify code we just delete all related parameters and than
		# recreate them if needed
		#
		self.del_simple_param('cpu.main-core')
		self.del_simple_param('cpu.corelist-workers')
		self.del_simple_param('buffers.buffers-per-numa')
		self.del_simple_param('dpdk.dev default.num-rx-queues')

		if num_workers == 0:
			return

		self.set_simple_param('cpu.main-core', 0)
		num_workers_str = "1" if num_workers == 1 else "1-%d" % (num_workers)
		self.set_simple_param('cpu.corelist-workers', num_workers_str)

		self.set_simple_param('dpdk.dev default.num-rx-queues', num_workers)

		# Based on analysis of vpp extras/vpp_config/extras/vpp_config.py:
		# 	buffers-per-numa = ((rx_queues * desc_entries) + (tx_queues * desc_entries)) * total_ports_per_numa * 2
		#
		desc_entries         = 1024             # Taken from vpp_config.py
		if not rx_queues:
			rx_queues        = num_workers      # We use RX queue per worker
		if not tx_queues:
			tx_queues        = num_workers      # We use TX queue per worker
		total_ports_per_numa = num_interfaces   # Port = Interface
		buffers = (rx_queues + tx_queues) * desc_entries * total_ports_per_numa * 2
		self.set_simple_param('buffers.buffers-per-numa', buffers)
