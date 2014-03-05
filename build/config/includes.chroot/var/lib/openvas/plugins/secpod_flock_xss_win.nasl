###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flock_xss_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Flock Browser Malformed Bookmark Cross site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute HTML code in the
  context of the affected browser, potentially allowing the attacker to steal
  cookie-based authentication credentials.
  Impact Level: Application";
tag_affected = "Flock versions 3.0 to 3.0.0.4093";
tag_insight = "The flaw is due to malformed favourite imported from an HTML file,
  imported from another browser, or manually created can bypass cross-origin
  protection, which has unspecified impact and attack vectors.";
tag_solution = "Upgrade to the Flock version 3.0.0.4094
  For updates refer to http://www.flock.com/";
tag_summary = "This host is installed with Flock browser and is prone to cross
  site scripting vulnerability.";

if(description)
{
  script_id(902313);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3202");
  script_bugtraq_id(42556);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Flock Browser Malformed Bookmark Cross site scripting Vulnerability");
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
  script_summary("Check for the version of Flock Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_flock_detect_win.nasl");
  script_require_keys("Flock/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://flock.com/security/");
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2010/08/flock-browser-3003989-malformed.html");
  exit(0);
}


include("version_func.inc");

flockVer = get_kb_item("Flock/Win/Ver");
if(!flockVer){
  exit(0);
}

# Check for Flock Version 3.x to 3.0.0.4093
if(version_in_range(version:flockVer, test_version:"3.0", test_version2:"3.0.0.4093")){
  security_warning(0);
}
