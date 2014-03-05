###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_extented_validation_info_disc_vuln_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# Opera Extended Validation Information Disclosure Vulnerabilities (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to steal sensitive security
  information.
  Impact Level: Application";
tag_affected = "Opera version before 11.51 on Linux";
tag_insight = "Multiple flaws are due to an error when loading content from trusted
  sources in an unspecified sequence that causes the address field and page
  information dialog to contain security information based on the trusted site
  and loading an insecure site to appear secure via unspecified actions related
  to Extended Validation.";
tag_solution = "Upgrade to Opera version 11.51 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera and is prone to information
  disclosure vulnerabilities.";

if(description)
{
  script_id(802830);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3388","CVE-2011-3389");
  script_bugtraq_id(49388);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-06 12:13:30 +0530 (Fri, 06 Apr 2012)");
  script_name("Opera Extended Validation Information Disclosure Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/74828");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/74829");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45791");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1025997");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1000/");

  script_description(desc);
  script_summary("Check for the version of Opera on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialization
operaVer = NULL;

## Get the version
operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version < 11.51
if(version_is_less(version:operaVer, test_version:"11.51")){
  security_warning(0);
}
