import json
import os.path
import xml.etree.ElementTree as elt

abs_path = os.path.abspath(os.path.dirname(__file__))
file_path = os.path.join(abs_path, "./apns-conf_new.xml")

def parse_apn():
    try:
        dictionary = {}
        content = elt.parse(file_path).getroot()
        for child in content:
            carrier = child.attrib['carrier'] if 'carrier' in child.attrib else None
            cur_mcc = child.attrib['mcc'] if 'mcc' in child.attrib else None
            cur_mnc = child.attrib['mnc'] if 'mnc' in child.attrib else None
            apn = child.attrib['apn'] if 'apn' in child.attrib else None
            if carrier and cur_mcc and cur_mnc:
                if 'MMS' not in carrier:
                    key = '%s-%s' % (cur_mcc, cur_mnc)
                    dictionary[key] = apn

        print("AAAA")
        with open(os.path.join(abs_path, "./result.json"), 'w') as fp:
            # json_object = json.dumps(dictionary, indent = 4)
            json.dump(dictionary, fp, indent=4, sort_keys=True)
            # json.dump(json_object, fp)
    except Exception as e:
        print(e)
        pass

parse_apn()