from __future__ import print_function
import argparse
from datetime import datetime
from pefile import PE

parser = argparse.ArgumentParser('Metadata from executable file')
parser.add_argument("-v", "--verbose", help="Increase verbosity of output",
                    action='store_true', default=False)
args = parser.parse_args()

while True:
    print("[+]Created By: Lumene Caleb \n[+]Student Number: 1902114243\n[+]Course: Computer Hacking and Forensic Investigations 3 CHFI3")
    print("[+]Lecturers: Eng Mwashi, Eng Simata\n[+]Project title: Windows Exe Metadata Forensics")
    print("##### NB: WHEN ADDING FILE PATH DONT USE DOUBLE QOUTES JUST ADD FILE LIKE SO: c/user/file.exe ####\n")
    #print("\n")

    exe_file = input("Enter the path to the executable file (or 'exit' to quit): ")

    if exe_file.lower() == 'exit':
        break

    try:
        pe = PE(exe_file)
        ped = pe.dump_dict()

        file_info = {}
        for structure in pe.FileInfo:
            if structure[0].Key == b'StringFileInfo':
                for s_table in structure[0].StringTable:
                    for key, value in s_table.entries.items():
                        if value is None or len(value) == 0:
                            value = "Unknown"
                        file_info[key] = value

        print("File Information: ")
        print("==================")
        for k, v in file_info.items():
            if isinstance(k, bytes):
                k = k.decode()
            if isinstance(v, bytes):
                v = v.decode()
            print("{}: {}".format(k, v))

        comp_time = ped['FILE_HEADER']['TimeDateStamp']['Value']
        comp_time = comp_time.split("[")[-1].strip("]")
        time_stamp, timezone = comp_time.rsplit(" ", 1)
        comp_time = datetime.strptime(time_stamp, "%a %b %d %H:%M:%S %Y")
        print("Compiled on {} {}".format(comp_time, timezone.strip()))

        for section in ped['PE Sections']:
            print("Section '{}' at {}: {}/{} {}".format(
                section['Name']['Value'], hex(section['VirtualAddress']['Value']),
                section['Misc_VirtualSize']['Value'],
                section['SizeOfRawData']['Value'], section['MD5'])
            )

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("\nImports: ")
            print("=========")
            for dir_entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = dir_entry.dll

                if not args.verbose:
                    print(dll.decode(), end=", ")
                    continue

                name_list = []
                for impts in dir_entry.imports:
                    if getattr(impts, "name", b"Unknown") is None:
                        name = b"Unknown"
                    else:
                        name = getattr(impts, "name", b"Unknown")
                    name_list.append([name.decode(), hex(impts.address)])

                name_fmt = ["{} ({})".format(x[0], x[1]) for x in name_list]
                print('- {}: {}'.format(dll.decode(), ", ".join(name_fmt)))

            if not args.verbose:
                print()

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("\nExports: ")
            print("=========")
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print('- {}: {}'.format(sym.name.decode(), hex(sym.address)))

        print("\n")

    except Exception as e:
        print("Error: {}".format(str(e)))
        continue
