# Standalone debug tool to find intersection of different traffic identification tags
# Usage: <program> arg1 arg2 arg3
# <arg1 - Category Name> <arg2 - Importance value> <arg3 - Service class value>
# arg value as 'any' indicates ignore (not to factor it in finding intersetion)

# Example: <program> auth-service medium any
# Outputs overlapping Traffic identifications of 'auth-service' + 'medium'

# TODO:
# 1. Think on need and scope to integrate as a CLI option in fwagent or fwdump
# 2. Better CLI input
# 3. Format output

from sqlitedict import SqliteDict
import sys

TRAFFIC_ID_DB = '/etc/flexiwan/agent/.traffic_identification.sqlite'

if len(sys.argv) != 4:
    print 'Usage: <program> <category_name or any> <importance or any> <service_class or any>'
    print 'Example: <program> auth-service medium any'
    exit(-1)

values = []
if sys.argv[1].lower() != 'any':
    category_dict = SqliteDict(TRAFFIC_ID_DB, 'category', flag='r')
    result = category_dict.get(sys.argv[1])
    category_dict.close()
    if result:
        values.append(result)
    else:
        print 'Category tag Not FOUND %s' % (sys.argv[1])
        exit(-1)

if sys.argv[2].lower() != 'any':
    importance_dict = SqliteDict(TRAFFIC_ID_DB, 'importance', flag='r')
    result = importance_dict.get(sys.argv[2])
    importance_dict.close()
    if result:
        values.append(result)
    else:
        print 'Importance tag Not FOUND %s' % (sys.argv[2])
        exit(-1)

if sys.argv[3].lower() != 'any':
    traffic_class_dict = SqliteDict(TRAFFIC_ID_DB, 'traffic_class', flag='r')
    result = traffic_class_dict.get(sys.argv[3])
    traffic_class_dict.close()
    if result:
        values.append(result)
    else:
        print 'Traffic Class tag Not FOUND %s' % (sys.argv[3])
        exit(-1)


if values:
    result = set.intersection(*values)
    traffic_id_dict = SqliteDict(TRAFFIC_ID_DB, 'traffic_id', flag='r')
    for out in result:
        info = traffic_id_dict.get(out)
        if info:
            print 'Traffic ID: ' + str(out)
            print info
        else:
            print 'CRITICAL Issue (Inconsistent DB): Traffic ID : %s not found in ID table' % (out)
            exit(-1)
    traffic_id_dict.close()
else:
    print 'No common intersection of tags found'
