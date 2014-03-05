###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM WebSphere Application Server (WAS) Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let attackers to conduct Cross-site scripting
  attacks.
  Impact Level: Application";
tag_affected = "IBM WAS Version 6.0 before 6.0.2.43, 6.1 before 6.1.0.33 and 7.0 before 7.0.0.11";
tag_insight = "The flaw is due to an error in the Administration Console, which
  allows remote attackers to inject arbitrary web script or HTML via
  unspecified vectors.";
tag_solution = "Upgrade to IBM WAS version 6.0.2.43, 6.1.0.33 or 7.0.0.11,
  For updates refer to http://www.ibm.com/developerworks/downloads/ws/was/";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to Cross-site
  Scripting vulnerability.";

if(description)
{
  script_id(902213);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-0778","CVE-2010-0779");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM WebSphere Application Server (WAS) Cross-site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://vul.hackerjournals.com/?p=10207");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/395192.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59646");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59647");

  script_description(desc);
  script_summary("Check for the version of IBM WebSphere Application Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
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
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

vers = get_kb_item(string("www/", port, "/websphere_application_server"));
if(isnull(vers)){
  exit(0);
}

if(version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.10") ||
   version_in_range(version: vers, test_version: "6.0", test_version2:"6.0.2.42") ||
   version_in_range(version: vers, test_version: "6.1", test_version2:"6.1.0.32")){
   security_warning(port:port);
}
