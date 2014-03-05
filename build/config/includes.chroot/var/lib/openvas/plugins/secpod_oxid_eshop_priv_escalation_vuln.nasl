###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oxid_eshop_priv_escalation_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# OXID eShop Community Edition Privilege Escalation Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers can exploit this issue to gain administrator privileges and
  access shop backend via specially crafted URLs.
  Impact Level: Application";
tag_affected = "OXID eShop Community Edition version 4.0 prior to 4.1.0.";
tag_insight = "User supplied data passed to an unspecified variable is not sanitised
  before processing.";
tag_solution = "Apply the patches or upgrade to version 4.1.0
  http://www.oxidforge.org/wiki/Category:Downloads";
tag_summary = "This host is installed with OXID eShop Community Edition
  and is prone to Privilege Escalation vulnerability.";

if(description)
{
  script_id(900933);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3112");
  script_name("OXID eShop Community Edition Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/385006.php");
  script_xref(name : "URL" , value : "http://www.oxidforge.org/wiki/Security_bulletins/2009-001");

  script_description(desc);
  script_summary("Check for the version of OXID eShop Community Edition");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_oxid_eshop_detect.nasl");
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

eshopPort = get_http_port(default:80);
if(!eshopPort)
{
  exit(0);
}

eshopVer = get_kb_item("www/" + eshopPort + "/OXID-eShop");

if(!isnull(eshopVer))
{
  eshopVer = eregmatch(pattern:"^(.+) under (/.*)$", string:eshopVer);
  if(eshopVer[1] =~ "^4\.")
  {
    if(version_is_less(version:eshopVer[1],test_version:"4.1.0")){
      security_hole(eshopPort);
    }
  }
}
