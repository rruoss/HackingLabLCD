###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_simple_machines_forum_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Simple Machines Forum Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Apply the patch or upgrade to version 1.1.13 or 2.0 RC5
  http://download.simplemachines.org/
  http://custom.simplemachines.org/mods/downloads/smf_patch_2.0-RC4_security.zip

  *****
  NOTE : Ignore this warning, if above mentioned fix is applied already.
  *****";

tag_impact = "Successful exploitation will allow attackers to obtain access or cause a
  denial of service or to conduct SQL injection attacks, obtain sensitive
  information.
  Impact Level: Application.";
tag_affected = "Simple Machines Forum (SMF) before 1.1.13 and 2.x before 2.0 RC5";
tag_insight = "Multiple flaws are due to,
  - An error in 'SSI.php', it does not properly restrict guest access.
  - An error in loadUserSettings function in 'Load.php', it does not properly
    handle invalid login attempts.
  - An error in EditNews function in 'ManageNews.php', which allow users to
    inject arbitrary web script or HTML via a save_items action.
  - An error in cleanRequest function in 'QueryString.php' and the
    constructPageIndex function 'in Subs.php'.
  - An error in PlushSearch2 function in 'Search.php', allow remote attackers
    to obtain sensitive information via a search.";
tag_summary = "The host is installed with Simple Machines Forum and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(902446);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-1127", "CVE-2011-1128", "CVE-2011-1129",
                "CVE-2011-1130", "CVE-2011-1131");
  script_bugtraq_id(48388);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Simple Machines Forum Multiple Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/03/02/4");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/02/22/17");
  script_xref(name : "URL" , value : "http://www.simplemachines.org/community/index.php?topic=421547.0");

  script_description(desc);
  script_summary("Check for the version of Simple Machines Forum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
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

## Get the default port
httpPort = get_http_port(default:80);
if(!httpPort){
  exit(0);
}

## Get the version From kb
ver = get_version_from_kb(port:httpPort, app:"SMF");
if(!ver){
  exit(0);
}

if(version_is_less(version:ver, test_version:"1.1.3")||
   version_in_range(version:ver, test_version:"2.0.RC", test_version2:"2.0.RC4")){
  security_hole(httpPort);
}