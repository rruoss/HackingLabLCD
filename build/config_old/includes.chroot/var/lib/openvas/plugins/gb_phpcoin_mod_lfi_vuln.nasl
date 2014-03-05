##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpcoin_mod_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpCOIN 'mod' Parameter Local File Include Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  and attacker can include arbitrary files.
  Impact Level: Application.";
tag_affected = "phpCOIN version 1.2.1 and prior";

tag_insight = "The flaw exists in 'mod.php' as it fails to properly sanitize user-supplied
  data, which allows remote attacker to include arbitrary files.";
tag_solution = "Upgrade to phpCOIN version 1.6.5 or higher";
tag_summary = "This host is running phpCOIN and is prone to local file include
  vulnerability.";

if(description)
{
  script_id(800736);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(38576);
  script_cve_id("CVE-2010-0953");
  script_name("phpCOIN 'mod' Parameter Local File Include Vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56721");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11641");

  script_description(desc);
  script_summary("Check for the version of phpCOIN");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpcoin_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");

## Get HTTP Port
phpPort = get_http_port(default:80);
if(!phpPort){
  exit(0);
}

## Get phpCOIN Version from KB
phpVer = get_kb_item("www/" + phpPort + "/phpCOIN");
if(!phpVer){
  exit(0);
}

if(phpVer != NULL)
{
  ## Check Version less then 1.2.1
  if(version_is_less(version:phpVer, test_version:"1.2.2")){
    security_hole(phpPort);
  }
}
