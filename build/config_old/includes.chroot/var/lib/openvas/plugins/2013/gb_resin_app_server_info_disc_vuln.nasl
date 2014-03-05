##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_resin_app_server_info_disc_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Resin Application Server Source Code Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to view its source code that
  might reveal sensitive information.
  Impact Level: Application";
tag_affected = "Resin Application Server version 4.0.36";


tag_insight = "The flaw is due to an improper sensitization of the 'file' parameter when
  used for reading help files. An attacker can exploit this vulnerability by
  directly requesting a '.jsp' file.";
tag_solution = "No solution or patch is available as of 10th June, 2013. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.caucho.com/download/";
tag_summary = "This host is running Resin Application Server and prone to source
  code disclosure vulnerability.";

if(description)
{
  script_id(803713);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-10 16:11:12 +0530 (Mon, 10 Jun 2013)");
  script_name("Resin Application Server Source Code Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121933");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013060064");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/codes/resin_scd.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5144.php");
  script_summary("Try to access the source code of Resin Application Server");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the application
banner = get_http_banner(port:port);
if("Server: Resin" >!< banner){
  exit(0);
}

url = '/resin-doc/viewfile/?file=index.jsp';

## Send the request and confirm the exploit
if(http_vuln_check(url:url, pattern:'resin-doc.*default-homepage', port:port,
  extra_check:make_list('getServerName', 'hasResinDoc', 'hasOrientation')))
{
  security_warning(port:port);
  exit(0);
}
