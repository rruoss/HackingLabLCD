##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_mult_vuln_apr11.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP System Management Homepage Multiple Vulnerabilities
#
# Authors:
# Antu  Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system and also cause Denial of Service (DoS).
  Impact Level: Application.";
tag_affected = "HP System Management Homepage (SMH) prior to 6.3";

tag_solution = "Apply patch or upgarde to HP SMH version 6.3 or later,
  For updates refer to http://www.hp.com/servers/manage/smh

  *****
  NOTE: Ignore this warning if patch is applied already.
  *****";

tag_insight = "The flaw is caused by unspecified errors with unknown attack vectors.";
tag_summary = "This host is running  HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(902413);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_cve_id("CVE-2011-1540", "CVE-2011-1541");
  script_bugtraq_id(47507, 47512);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("HP System Management Homepage Multiple Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100629/HPSBMA02662-SSRT100409.txt");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

## this nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

smhPort = get_http_port(default:2301);
if(!get_port_state(smhPort)){
  exit(0);
}

## Get HP SMH version from KB
smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer != NULL)
{
  ## Check HP SMH version < 6.3
  if(version_is_less(version:smhVer, test_version:"6.3")){
    security_hole(smhPort);
  }
}
