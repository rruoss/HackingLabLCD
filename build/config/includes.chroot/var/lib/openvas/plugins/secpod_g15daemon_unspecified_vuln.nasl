###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_g15daemon_unspecified_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# G15Daemon Unspecified Vulnerability
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
tag_impact = "Unknown impact.
  Impact Level: Application";
tag_affected = "G15Daemon version prior to 1.9.4";
tag_insight = "Multiple unspecified vulnerabilities exist, details are not available.";
tag_solution = "Upgrade to version 1.9.4 or latest
  http://g15daemon.sourceforge.net/";
tag_summary = "This host has G15Daemon installed and is prone to Unspecified
  vulnerability.";

if(description)
{
  script_id(900854);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-18 08:01:03 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-7197");
  script_name("G15Daemon Unspecified Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/40528");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/apps/freshmeat/2008-01/0019.html");

  script_description(desc);
  script_summary("Check for the version of G15Daemon");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_g15daemon_detect.nasl");
  script_require_keys("G15Daemon/Ver");
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

g15dVer = get_kb_item("G15Daemon/Ver");
if(!g15dVer) {
  exit(0);
}

# Check for G15Daemon version < 1.9.4
if(version_is_less(version:g15dVer, test_version:"1.9.4")){
  security_hole(0);
}
