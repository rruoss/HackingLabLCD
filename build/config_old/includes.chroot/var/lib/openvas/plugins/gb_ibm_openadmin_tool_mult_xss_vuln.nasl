##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_openadmin_tool_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM Open Admin Tool 'index.php' Multiple Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site
  and steal the victim's cookie-based authentication credentials.
  Impact Level: Application.";
tag_affected = "IBM OpenAdmin Tool (OAT) version before 2.72";

tag_insight = "The flaws are due to the improper validation of user supplied input
  via 'host', 'port', 'username', 'userpass' and 'informixserver' parameters
  in 'index.php'.";
tag_solution = "Upgrade to IBM OpenAdmin Tool (OAT) version 2.72 or later
  For updates refer to https://www14.software.ibm.com/webapp/iwm/web/reg/download.do?source=swg-informixfpd&lang=en_US&S_PKG=dl&cp=UTF-8";
tag_summary = "This host is running IBM Open Admin Tool and is prone to multiple
  cross-site scripting vulnerabilities.";

if(description)
{
  script_id(802159);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)");
  script_cve_id("CVE-2011-3390");
  script_bugtraq_id(49364);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM Open Admin Tool 'index.php' Multiple Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69488");
  script_xref(name : "URL" , value : "http://voidroot.blogspot.com/2011/08/xss-in-ibm-open-admin-tool.html");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104617/ibmopenadmin-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/519468/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of IBM Open Admin Tool");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_openadmin_tool_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!get_port_state(port)){
  exit(0);
}

## GET the version from KB
ver = get_kb_item("www/" + port + "/IBM/Open/Admin/Tool");
if(!ver){
  exit(0);
}

## Check the IBM Open Admin Tool less than 2.72
if(version_is_less(version:ver, test_version:"2.72")){
  security_warning(port);
}
