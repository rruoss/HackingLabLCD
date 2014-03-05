###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_admin_console_csrf_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM WebSphere Application Server Multiple CSRF Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote users to gain sensitive information
  and conduct other malicious activities.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) 7.0.0.13 and prior.";
tag_insight = "The flaws are due to by improper validation of user-supplied input
  in the Global Security panel and master configuration save functionality.
  which allows attacker to force a logged-in administrator to perform unwanted
  actions.";
tag_solution = "No solution or patch is available as of 21th July 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/webservers/appserv/was/";
tag_summary = "The host is running IBM WebSphere Application Server and is prone
  to cross-site request forgery vulnerabilities.";

if(description)
{
  script_id(902610);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2010-3271");
  script_bugtraq_id(48305);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("IBM WebSphere Application Server Multiple CSRF Vulnerabilities");
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
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44909");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68069");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/IBM-WebSphere-CSRF");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## To get IBM WebSphere Application Server version
vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

## Checking IBM WebSphere Application Server version 7.0.0.13 and prior
if(version_is_less_equal(version:vers, test_version:"7.0.0.13")){
  security_hole(port:port);
}
