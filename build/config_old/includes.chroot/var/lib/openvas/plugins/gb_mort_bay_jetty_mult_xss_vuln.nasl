###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mort_bay_jetty_mult_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2012-02-03
#  - Added script_require_keys
#  - Using http_vuln_check to confirm vulnerability
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
tag_solution = "No solution or patch is available as of 01st, February, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mortbay.org/jetty/

  Workaround:
  Apply workaround from below link,
  http://seclists.org/fulldisclosure/2009/Oct/319";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site
  allowing Cross-Site Scripting attacks.
  Impact Level: Application.";
tag_affected = "Jetty version 6.0.x to 6.1.21";
tag_insight = "Multiple flaws exists due to error in 'PATH_INFO' parameter, it is not
  properly sanitised data before used via the default URI under 'jspsnoop/',
  'jspsnoop/ERROR/', 'jspsnoop/IOException/' and 'snoop.jsp'";
tag_summary = "This host is running Mort Bay Jetty and is prone to multiple Cross
  Site Scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800285";
CPE = "cpe:/a:mortbay:jetty";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4612");
  script_name("Mort Bay Jetty Multiple Cross Site Scripting Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2009/Oct/319");
  script_xref(name : "URL" , value : "http://www.ush.it/team/ush/hack_httpd_escape/adv.txt");

  script_description(desc);
  script_summary("Check if Mort Bay Jetty is vulnerable to XSS attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_jetty_detect.nasl");
  script_family("Web application abuses");
  script_require_keys("Jetty/installed");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
jettyPort =  get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!jettyPort){
  exit(0);
}

## Try XSS attack
url = "/test/jsp/dump.jsp?<script>alert(document.cookie)</script>";
if(http_vuln_check(port:jettyPort, url:url, pattern:"<script>alert\(document" + ".cookie\)</script>")){
  security_warning(jettyPort);
}
