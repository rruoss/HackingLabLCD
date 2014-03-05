##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitdefender_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# BitDefender Internet Security 2009 XSS Vulnerability
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary script codes
  in a local context by including a malicious HTML file placed on the local
  system.
  Impact Level: System/Application";
tag_affected = "BitDefender Internet Security version 2009 build 12.0.11.4 and prior.";
tag_insight = "BitDefender Internet Security product fails to properly sanitise the input
  passed through the filename (.rar or .zip archives) of an infected executable
  before being used to output infection details.";
tag_solution = "No solution or patch is available as of 19th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bitdefender.com";
tag_summary = "This host is installed with BitDefender Internet Security and
  is prone to cross site scripting vulnerability.";

if(description)
{
  script_id(900327);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-20 07:08:52 +0100 (Fri, 20 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0850");
  script_bugtraq_id(33921);
  script_name("BitDefender Internet Security 2009 XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34082");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0557");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501277/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of BitDefender Internet Security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("secpod_bitdefender_prdts_detect.nasl");
  script_require_keys("BitDefender/InetSec/Ver");
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

bitVer = get_kb_item("BitDefender/InetSec/Ver");
if(!bitVer){
  exit(0);
}

# Check for version 12.0.11.4 and prior
if(version_is_less_equal(version:bitVer, test_version:"12.0.11.4")){
  security_warning(0);
}
