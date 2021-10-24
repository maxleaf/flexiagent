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


# This script prints onto screen dump created by cProfiler::dump_stats(<filename>) command.
#
# Overview
# https://docs.python.org/3/library/profile.html
# https://www.machinelearningplus.com/python/cprofile-how-to-profile-your-python-code/
#
# There are following ways to invoke python cProfile:
# ------------------------------------------------------------------------------
# - python -m cProfile [-o output_file] [-s sort_order] (-m module | <script-to-profile.py>)
# - cProfile.run('main()')
# - import cProfile, pstats
#   p = cProfile.Profile()
#   p.enable()
#   main()
#   p.disable()
#   pstats.Stats(p).sort_stats('ncalls').print_stats()
#
#
# The output of Stats::print_stats():
# ------------------------------------------------------------------------------
#
#     ncalls  tottime  percall  cumtime  percall filename:lineno(function)
#         1    0.000    0.000    0.000    0.000 <string>:1(<module>)
#         1    0.000    0.000    0.000    0.000 {built-in method builtins.exec}
#
#   where
#     ncalls : Shows the number of calls made
#
#     tottime: Total time taken by the given function.
#              Note that the time made in calls to sub-functions are excluded.
#
#     percall: Total time / No of calls. ( remainder is left out )
#
#     cumtime: Unlike tottime, this includes time spent in this and all subfunctions
#              that the higher-level function calls. It is most useful and is accurate
#     		  for recursive functions.
#
#     percall following cumtime -  is calculated as the quotient of cumtime divided
#              by primitive calls. The primitive calls include all the calls
#              that were not included through recursion.
#
#   Possible columns (argument of Stats::sort_stats()):
#      string       enum                meaning
#     -----------------------------------------------------
#     'calls'       SortKey.CALLS       call count
#     'cumulative'  SortKey.CUMULATIVE  cumulative time
#     'cumtime'     N/A                 cumulative time
#     'file'        N/A                 file name
#     'filename'    SortKey.FILENAME    file name
#     'module'      N/A                 file name
#     'ncalls'      N/A                 call count
#     'pcalls'      SortKey.PCALLS      primitive call count
#     'line'        SortKey.LINE        line number
#     'name'        SortKey.NAME        function name
#     'nfl'         SortKey.NFL         name/file/line
#     'stdname'     SortKey.STDNAME     standard name
#     'time'        SortKey.TIME        internal time
#     'tottime'     N/A internal        time
#
#   Few examples of statistic sorting & partial print:
#     - pstats.Stats(profiler)::sort_stats(pstats.SortKey.NAME)
#     - pstats.Stats(profiler)::p.sort_stats(SortKey.TIME).print_stats(10)
#     - pstats.Stats(profiler)::p.sort_stats(SortKey.TIME, SortKey.CUMULATIVE).print_stats(.5, 'init')
#
#
# Save profiler output into file and print later (using this script)
# ------------------------------------------------------------------------------
#   Dump into file:
#	    cProfiler::dump_stats('profile.dmp')
#
#   Print file on STDOUT in human readable form:
#       ps = pstats.Stats('profile.dmp')
#       ps.strip_dirs().sort_stats('cumulative').print_stats()
#
#   Convert dump file into text file with human readable data:
#       out_stream = open('profile.txt', 'w')
#       ps = pstats.Stats('profile.dmp', stream=out_stream)
#       ps.strip_dirs().sort_stats('cumulative').print_stats()
#

sort_keys = {
     'calls':       { 'descr': "call count: the number of calls made" },
     'cumtime':     { 'descr': "cumulative time: time spent in this and all subfunctions" },
     'filename':    { 'descr': "file name" },
     'pcalls':      { 'descr': "primitive call count: calls that were not induced via recursion" },
     'line':        { 'descr': "line number" },
     'name':        { 'descr': "function name" },
     'nfl':         { 'descr': "name/file/line" },
     'tottime':     { 'descr': "total time - time spent in function excluding time in sub-functions" },
}



import glob
import os
import pstats
import sys

def main(args):

    if os.path.isfile(args.dump_filename):
        in_filenames = [args.dump_filename]
    elif os.path.isdir(args.dump_filename):
        in_filenames = glob.glob(f"{args.dump_filename}/*.dmp")
    else:
        in_filenames = glob.glob(args.dump_filename)

    for in_filename in in_filenames:

        out_stream = sys.stdout

        if args.out_filename:
            # '--out' option without filename feeds args.out_filename with 'default'.
            # In this case we use same name as the input file has, just replace
            # extension with "*.txt"
            # If '--out' is not provided at all, the output is printed onto screen.
            #
            out_filename = os.path.splitext(in_filename)[0]+'.txt' \
                if args.out_filename == 'default' \
                else args.out_filename

            out_stream = open(out_filename, 'w')

        ps = pstats.Stats(in_filename, stream=out_stream)
        ps.strip_dirs().sort_stats(args.sort_key).print_stats(int(args.num_of_lines))

        if out_stream != sys.stdout:
            out_stream.close()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='cProfiler dump to text convertor')
    parser.add_argument('-f', '--input_file', dest='dump_filename', default='*.dmp',
                        help="dump file generated by cProfiler::dump_stats() or pattern\
                              If directory is provided, all found *.dmp files will be converted")
    parser.add_argument('-l', '--legend', action='store_true',
                        help="info on available sort keys")
    parser.add_argument('-n', dest='num_of_lines', default=15,
                        help="number of top functions to display (default=15)")
    parser.add_argument('-o', '--out', dest='out_filename', nargs='?', const='default',
                        help="output file. If provided with no value, use --file value with '.txt' extension")
    parser.add_argument('-s', '--sort', dest='sort_key', default='cumtime',
                        choices=sorted(list(sort_keys.keys())),
                        help="key to sort output by")
    args = parser.parse_args()

    if args.legend:
        print("possible sort keys:")
        for k in sorted(list(sort_keys.keys())):
            print(f" {k:{10}}: {sort_keys[k]['descr']}")
        sys.exit(0)

    main(args)
