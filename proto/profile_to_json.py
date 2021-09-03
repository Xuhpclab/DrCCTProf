#!/usr/bin/env python3

from google.protobuf import json_format
import profile_pb2
import sys
import json


input_file_path = sys.argv[1]
out_file_path = input_file_path + ".json"

with open(input_file_path, 'rb') as f:
    buf = f.read()
    profile = profile_pb2.Profile()
    profile.ParseFromString(buf)
    json_result = json_format.MessageToJson(profile)
    with open(out_file_path, 'w') as fw:
        fw.write(json_result)
