###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap6_dns_random_srcport.nasl 10 2013-10-27 10:03:59Z jan $
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: 
# Script: Brandon Enright <bmenrigh@ucsd.edu>\n
# porttest.dns-oarc.net: Duane Wessels <wessels@dns-oarc.net>
# 
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
tag_summary = "Checks a DNS server for the predictable-port recursion vulnerability. Predictable source ports can
make a DNS server vulnerable to cache poisoning attacks (see CVE-2008-1447).

The script works by querying porttest.dns-oarc.net (see https://www.dns-
oarc.net/oarc/services/porttest).  Be aware that any targets against which this script is run will
be sent to and potentially recorded by one or more DNS servers and the porttest server. In addition
your IP address will be sent along with the porttest query to the DNS server running on the target.";

if(description)
{
    script_id(803532);
    script_version("$Revision: 10 $");
    script_tag(name:"cvss_base", value:"6.4");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:03:59 +0100 (So, 27. Okt 2013) $");
    script_tag(name:"creation_date", value:"2013-02-28 19:00:21 +0530 (Thu, 28 Feb 2013)");
    script_name("Nmap NSE 6.01: dns-random-srcport");
    desc = "
    Summary:
    " + tag_summary;

    script_description(desc);

    script_summary("Nmap NSE 6.01: dns-random-srcport");
    script_category(ACT_ATTACK);
    script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
    script_family("Nmap NSE");



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
## DNS Port
port = 53;
if(! get_udp_port_state(port)){
  exit(0);
}


argv = make_list("nmap", "-sU", "--script=dns-random-srcport.nse",
                                         "-p", port, get_host_ip());

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

  if("dns-random-srcport" >< result) {
    msg = string('Result found by Nmap Security Scanner (dns-random-srcport.nse) ',
                'http://nmap.org:\n\n', result);
    security_hole(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n', 'nmap ', argv);
  log_message(data: msg, port:port);
}