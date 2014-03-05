###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap6_snmp_brute.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Philip Pickering, Gorjan Petrovski, Patrik Karlsson
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Attempts to find an SNMP community string by brute force guessing.

This script opens a sending socket and a sniffing pcap socket in parallel  threads. The sending
socket sends the SNMP probes with the community strings, while the pcap socket sniffs the network
for an answer to the probes. If  valid community strings are found, they are added to the creds
database and reported in the output.

The script takes the 'snmp-brute.communitiesdb' argument that allows the user to define
the file that contains the community strings to be used. If not defined, the default wordlist used
to bruteforce the SNMP community strings is 'nselib/data/snmpcommunities.lst'. In case
this wordlist does not exist, the script falls back to 'nselib/data/passwords.lst'

No output is reported if no valid account is found.


SYNTAX:

userdb:  The filename of an alternate username database.


snmpcommunity:  The community string to use. If not given, it is
''public'', or whatever is passed to 'buildPacket'.


passdb:  The filename of an alternate password database.


snmp-brute.communitiesdb:  The filename of a list of community strings to try.



unpwdb.passlimit:  The maximum number of passwords
'passwords' will return (default unlimited).


unpwdb.userlimit:  The maximum number of usernames
'usernames' will return (default unlimited).


unpwdb.timelimit:  The maximum amount of time that any iterator will run
before stopping. The value is in seconds by default and you can follow it
with 'ms', 's', 'm', or 'h' for
milliseconds, seconds, minutes, or hours. For example,
'unpwdb.timelimit=30m' or 'unpwdb.timelimit=.5h' for
30 minutes. The default depends on the timing template level (see the module
description). Use the value '0' to disable the time limit.";

if(description)
{
    script_id(803542);
    script_version("$Revision: 10 $");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2013-02-28 19:00:31 +0530 (Thu, 28 Feb 2013)");
    script_name("Nmap NSE 6.01: snmp-brute");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE 6.01: snmp-brute");
    script_category(ACT_ATTACK);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE");

    script_add_preference(name:"userdb", value:"", type:"entry");
    script_add_preference(name:"snmpcommunity", value:"", type:"entry");
    script_add_preference(name:"passdb", value:"", type:"entry");
    script_add_preference(name:"snmp-brute.communitiesdb", value:"", type:"entry");
    script_add_preference(name:"unpwdb.passlimit", value:"", type:"entry");
    script_add_preference(name:"unpwdb.userlimit", value:"", type:"entry");
    script_add_preference(name:"unpwdb.timelimit", value:"", type:"entry");

    script_dependencies("toolcheck.nasl");
    script_mandatory_keys("Tools/Present/nmap6.01");
    script_mandatory_keys("Tools/Launch/nmap_nse");

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}

# The corresponding NSE script doesn't belong to the 'safe' category
if (safe_checks()) exit(0);


# Get the preferences
i = 0;

## SNMP Port
port = 161;

pref = script_get_preference("userdb");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'userdb', '=', pref, '"');
}
pref = script_get_preference("snmpcommunity");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'snmpcommunity', '=', pref, '"');
}
pref = script_get_preference("passdb");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'passdb', '=', pref, '"');
}
pref = script_get_preference("snmp-brute.communitiesdb");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'snmp-brute.communitiesdb', '=', pref, '"');
}
pref = script_get_preference("unpwdb.passlimit");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'unpwdb.passlimit', '=', pref, '"');
}
pref = script_get_preference("unpwdb.userlimit");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'unpwdb.userlimit', '=', pref, '"');
}
pref = script_get_preference("unpwdb.timelimit");
if (!isnull(pref) && pref != "") {
  args[i++] = string('"', 'unpwdb.timelimit', '=', pref, '"');
}

argv = make_list("nmap", "-sU", "--script=snmp-brute.nse", "-p", port,
                  get_host_ip());

if(i > 0)
{
  scriptArgs= "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv,scriptArgs);
}

## Run nmap and Get the Result
res = pread(cmd: "nmap", argv: argv);

if(res)
{
  foreach line (split(res))
  {
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("snmp-brute" >< result) {
    msg = string('Result found by Nmap Security Scanner (snmp-brute.nse) ',
                'http://nmap.org:\n\n', result);
    security_hole(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n', 'nmap ', argv);
  log_message(data: msg, port:port);
}