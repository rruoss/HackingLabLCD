###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_admin_console_unspecified_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM WebSphere Application Server Administration Console DoS vulnerability
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
tag_solution = "Apply the fix pack 6.1.0.33 or later,
  http://www-01.ibm.com/support/docview.wss?uid=swg27007951

  *****
  NOTE: Please ignore this warning if the patch is applied.
  *****";

tag_impact = "Successful exploitation will allow remote authenticated users to cause a
  denial of service (CPU consumption) via a crafted URL.
  Impact Level: Application";
tag_affected = "IBM WebSphere Application Server (WAS) 6.1 before 6.1.0.33";
tag_insight = "The flaw is due to unspecified error in the administrative console,
  which allows attackers to cause a denial of service.";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(902252);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-0781");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("IBM WebSphere Application Server Administration Console DoS vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61890");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM11807");

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
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

if(version_in_range(version: vers, test_version: "6.1", test_version2:"6.1.0.32")){
  security_warning(port:port);
}
