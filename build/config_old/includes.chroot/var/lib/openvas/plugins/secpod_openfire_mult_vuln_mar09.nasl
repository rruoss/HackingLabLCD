##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openfire_mult_vuln_mar09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Openfire Multiple Vulnerabilities (Mar09)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker cause multiple attacks in
  the context of the application i.e. Cross site scripting, disclosure of
  sensitive information, phishing attacks through the affected parameters.

  Impact level: Application/Network";

tag_affected = "Openfire version prior to 3.6.1";
tag_insight = "Multiple flaws are due to,
  - error in the AuthCheckFilter which causes access to administrative
    resources without admin authentication.
  - error in the type parameter inside the file 'sipark-log-summary.jsp'
    which causes SQL Injection attack.
  - error in the 'login.jsp' URL parameter which accept malicious chars
    as input which causes XSS attack.
  - error in the SIP-Plugin which is deactivated by default which lets the
    attack install the plugin by using admin authentication bypass methods.";
tag_solution = "Upgrade to the version 3.6.1 or later.
  http://www.igniterealtime.org/downloads/index.jsp";
tag_summary = "This host is running Openfire and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900484);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6511", "CVE-2008-6510", "CVE-2008-6508", "CVE-2008-6509");
  script_bugtraq_id(32189);
  script_name("Openfire Multiple Vulnerabilities (Mar09)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32478");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7075");
  script_xref(name : "URL" , value : "http://www.andreas-kurtz.de/advisories/AKADV2008-001-v1.0.txt");
  script_xref(name : "URL" , value : "http://www.igniterealtime.org/builds/openfire/docs/latest/changelog.html");

  script_description(desc);
  script_summary("Check for the version of Openfire");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_detect.nasl");
  script_require_ports("Services/www", 9090);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

firePort = get_http_port(default:9090);
if(!firePort){
  exit(0);
}

fireVer = get_kb_item("www/" + firePort + "/Openfire");
if(fireVer != NULL)
{
  # Grep for Openfire version prior to 3.6.1
  if(version_is_less(version:fireVer, test_version:"3.6.1")){
    security_hole(firePort);
  }
}
