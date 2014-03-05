###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mahara_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mahara Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain sensitive information
  in the affected web application.
  Impact Level: Application";
tag_affected = "Mahara version 1.1 before 1.1.5";
tag_insight = "- The application fails to apply permission checks when saving a view that 
    contains artefacts, which allows remote authenticated users to read
    another user's artefact.";
tag_solution = "Upgrade to Mahara version 1.1.5 or later
  https://eduforge.org/projects/mahara/";
tag_summary = "This host is running Mahara and is prone to Information Disclosure
  Vulnerability.";

if(description)
{
  script_id(900383);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2171");
  script_name("Mahara Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://mahara.org/interaction/forum/topic.php?id=753");

  script_description(desc);
  script_summary("Check for the version of Mahara");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_mahara_detect.nasl");
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

maharaPort = get_http_port(default:80);
if(!maharaPort){
  exit(0);
}

maharaVer = get_kb_item("www/"+ maharaPort + "/Mahara");
if(!maharaVer){
  exit(0);
}

ver = eregmatch(pattern:"^(.+) under (/.*)$", string:maharaVer);
if(ver[1] != NULL)
{
  # Check for Mahara version 1.1 < 1.1.5
  if(version_in_range(version:ver[1], test_version:"1.1",
                                      test_version2:"1.1.4")){
    security_warning(maharaPort);
  }
}
