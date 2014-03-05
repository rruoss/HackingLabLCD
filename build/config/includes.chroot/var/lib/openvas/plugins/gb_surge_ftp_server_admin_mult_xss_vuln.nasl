##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_surge_ftp_server_admin_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Surge-FTP Admin Multiple Reflected Cross-site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary html
  or scripting code in a user's browser session in the context of a vulnerable
  application/website.
  Impact Level: Application";
tag_affected = "Surge-FTP version 23b6";
tag_insight = "Input passed through the POST parameters 'fname', 'last', 'class_name',
  'filter', 'domainid', and 'classid' in '/cgi/surgeftpmgr.cgi' is not
  sanitized properly. Allowing the attacker to execute HTML code into admin's
  browser session.";
tag_solution = "No solution or patch is available as of 18th, August 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://netwinsite.com/ftp/surgeftp/";
tag_summary = "This host is running Surge-FTP Server and is prone to multiple
  reflected cross-site scripting vulnerabilities.";

if(description)
{
  script_id(801970);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Surge-FTP Admin Multiple Reflected Cross-site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104047/surgeftp3b6-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityhome.eu/os/winnt/exploit.php?eid=8349105614e4a2458040b68.10913730");

  script_description(desc);
  script_summary("Check for the version of Surge-FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("FTP");
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
include("version_func.inc");

## Get the default port
port = get_kb_item("Services/ftp");
if(!port){
  port = 21;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the server
banner = get_ftp_banner(port);
if("SurgeFTP" >!< banner){
  exit(0);
}

## Grep the version from banner
vers = eregmatch(pattern:"SurgeFTP.*\(Version ([^)]+)\)", string: banner);
if(isnull(vers[1])){
  exit(0);
}

## Check the Surge-FTP version 2.3b6
if(version_is_equal(version:vers[1], test_version:"2.3b6")){
  security_warning(port:port);
}
