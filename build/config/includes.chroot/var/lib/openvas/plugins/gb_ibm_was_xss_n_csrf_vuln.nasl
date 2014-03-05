###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_xss_n_csrf_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM WebSphere Application Server (WAS) XSS and CSRF Vulnerabilities
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
tag_solution = "Apply Fix Pack 7.0.0.13 and 6.1.0.35 or later,
  http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27004980

  *****
  NOTE : Ignore this warning, if above workaround has been applied.
  *****";

tag_impact = "Successful exploitation will let attackers to conduct cross-site scripting
  and cross-site request forgery attacks.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server versions 6.1 before 6.1.0.35 and
  7.0 before 7.0.0.13.";
tag_insight = "- A cross-site scripting vulnerability exists in the administrative console
    due to improper filtering on input values.
  - An input sanitation error in the administrative console can be exploited
    to conduct cross-site request forgery attacks.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801646);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-0783", "CVE-2010-0785");
  script_bugtraq_id(44670);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("IBM WebSphere Application Server (WAS) XSS and CSRF Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42136");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Nov/1024686.html");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27004980");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Get Version from KB
vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

## Check for IBM WebSphere Application Server versions
if(version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.12")||
   version_in_range(version: vers, test_version: "6.0", test_version2:"6.1.0.34")) {
  security_hole(port:port);
}
