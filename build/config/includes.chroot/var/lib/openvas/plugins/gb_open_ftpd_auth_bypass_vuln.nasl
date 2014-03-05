###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_ftpd_auth_bypass_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Open-FTPD Authentication Bypass Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions and execute FTP commands without any authentication.
  Impact Level: Application";
tag_affected = "Open&Compact FTP Server (Open-FTPD) Version 1.2 and prior.";
tag_insight = "The flaw is due to access not being restricted to various FTP commands
  before a user is properly authenticated. This can be exploited to execute FTP
  commands without any authentication.";
tag_solution = "No solution or patch is available as of 12th July, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/open-ftpd/";
tag_summary = "This host is running Open&Compact FTP Server (Open-FTPD) and is
  prone to authentication bypass vulnerability.";

if(description)
{
  script_id(801228);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2620");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Open-FTPD Authentication Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13932");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40284");

  script_description(desc);
  script_summary("Determine if Open-FTPD is prone to Authentication Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");

## Get FTP port
port = get_kb_item("Services/ftp");
if(!port) {
  port = 21;
}

## Check port status
if(!get_port_state(port)) {
  exit(0);
}

## Confirm Open-FTPD
banner = get_ftp_banner(port:port);
if("Gabriel's FTP Server" >!< banner) {
  exit(0);
}

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Try to execute LIST command without authentication
ftp_send_cmd(socket:soc, cmd:"LIST");
result = ftp_recv_listing(socket:soc);
close(soc);

## Check the FTP status message
if("226 Transfert Complete" >< result)
{
  security_hole(port:port);
  exit(0);
}
