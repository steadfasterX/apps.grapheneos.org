#!/usr/bin/env python3

import os
import re
import shlex
import shutil
import subprocess
import sys

def load_signature(apk_path):
    apksigner_output = subprocess.check_output(["apksigner", "verify", "--print-certs", "--verbose", apk_path])
    sig_hash = None
    for line in apksigner_output.split(b'\n'):
        split = re.split("^Signer #[0-9]+ certificate SHA-256 digest: ", line.decode())
        if (len(split) == 2):
            if (sig_hash is not None):
                # Intentionally don't support APKs that have more than one signer
                raise Exception(apk_path + " has more than one signer")
            sig_hash = split[1]

    if sig_hash is None:
        raise Exception("didn't find signature of " + apk_path)

    return sig_hash

def import_apk(path, source, channel):
    print("\nimporting " + path + " (source: %s, channel: %s)" % (source, channel))

    badging = subprocess.check_output(["aapt2", "dump", "badging", path])
    lines = badging.split(b"\n")

    version = None
    pkg_name = None
    abi = None
    is_split = False

    for kv in shlex.split(lines[0].decode()):
        if kv.startswith("versionCode"):
            version = kv.split("=")[1]
        elif kv.startswith("name"):
            pkg_name = kv.split("=")[1]
        elif kv.startswith("split"):
            is_split = True

    assert version != None
    assert pkg_name != None

    base_dir = "apps/packages/" + pkg_name
    dest_dir = base_dir + "/" + version

    if not os.path.isdir(dest_dir):
        os.makedirs(dest_dir)

    with open(dest_dir + "/props.toml", "w") as f:
        f.write('channel = "' + channel + '"\n')

    if is_split:
        shutil.copy(path, dest_dir)
        print("copied to " + dest_dir)
    else:
        dest_path = dest_dir + "/base.apk"
        shutil.copyfile(path, dest_path)
        print("copied to " + dest_path)

    sig = []
    sig.append(load_signature(dest_dir + "/base.apk"))

    with open(base_dir + "/common-props.toml", "w") as f:
        f.write("signatures = " + str(sig) + "\n")
        f.write('source = "' + source + '"\n')

def main():
    import_apk(path=sys.argv[1], source=sys.argv[2], channel=sys.argv[3])

main()
