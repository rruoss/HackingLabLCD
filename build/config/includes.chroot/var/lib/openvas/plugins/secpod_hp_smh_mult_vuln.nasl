###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP System Management Homepage Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to obtain sensitive information
  or to redirect users to arbitrary web sites and conduct phishing attacks.";
tag_affected = "HP System Management Homepage versions prior to 6.2 on all platforms.";
tag_insight = "The flaws are due to:
   - An unspecified error in the application, allows remote attackers to
     obtain sensitive information via unknown vectors.
   - An open redirect vulnerability in the application, allows remote
     attackers to redirect users to arbitrary web sites and conduct phishing
     attacks via unspecified vectors.";
tag_solution = "Upgrade to HP System Management Homepage 6.2 or later,
  http://h18000.www1.hp.com/products/servers/management/agents/index.html";
tag_summary = "This host is running HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(902257);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3284", "CVE-2010-3283");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
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


  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=128525531721328&amp;w=2");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=128525419119241&amp;w=2");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

smhPort = get_http_port(default:2301);
if(!get_port_state(smhPort)){
  exit(0);
}

smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer != NULL)
{
  if(version_is_less(version:smhVer, test_version:"6.2")){
    security_warning(smhPort);
  }
}
