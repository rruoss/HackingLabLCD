###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_axon_virtual_pbx_mult_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Axon Virtual PBX Multiple Cross Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will let the attackers execute arbitrary HTML and
  script code in the affected user's browser session.
  Impact Level: Application";
tag_affected = "Axon Virtual PBX version 2.10 and 2.11";
tag_insight = "The input passed into 'onok' and 'oncancel' parameters in the logon program
  is not properly sanitised before being returned to the user.";
tag_solution = "Upgrade to Axon Virtual PBX version 2.13 or later
  For updates refer to http://www.nch.com.au/pbx/index.html";
tag_summary = "This host has Axon Virtual PBX installed and is prone to Multiple XSS
  vulnerabilities.";

if(description)
{
  script_id(900984);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4038");
  script_name("Axon Virtual PBX Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37157/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/387986.php");

  script_description(desc);
  script_summary("Check for the version of Axon Virtual PBX");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_axon_virtual_pbx_detect.nasl");
  script_require_keys("Axon-Virtual-PBX/Ver");
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

axonPort = get_http_port(default:81);
if(!get_port_state(axonPort)){
  exit(0);
}

banner = get_http_banner(port:axonPort);
if(("NCH Software" >< banner) && ("Axon" >< banner))
{
  axonVer = get_kb_item("Axon-Virtual-PBX/Ver");
  # Check for Axon Virtual PBX version is 2.10 or 2.11
  if(axonVer =~ "2.1(0|1)"){
    security_warning(axonPort);
  }
}

