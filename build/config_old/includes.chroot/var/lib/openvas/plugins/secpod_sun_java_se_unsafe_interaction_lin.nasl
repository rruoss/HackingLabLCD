##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_se_unsafe_interaction_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Unsafe Interaction In Sun Java SE Abstract Window Toolkit (Linux)
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
tag_impact = "Successful attacks will allow attackers to trick a user into interacting
  unsafely with an untrusted applet.
  Impact Level: System/Application";
tag_affected = "Sun Java SE version 6.0 before Update 15 on Linux.";
tag_insight = "An error in the Abstract Window Toolkit (AWT) implementation in on Linux (X11)
  does not impose the intended constraint on distance from the Security Warning
  Icon.";
tag_solution = "Upgrade to Java SE version 6 Update 15
  http://java.sun.com/javase/downloads/index.jsp";
tag_summary = "This host is installed with Sun Java SE and is prone to Unsafe
  Interaction.";

if(description)
{
  script_id(900821);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2718");
  script_name("Unsafe Interaction In Sun Java SE Abstract Window Toolkit (Linux)");
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
  script_xref(name : "URL" , value : "http://java.sun.com/javase/6/webnotes/6u15.html");

  script_description(desc);
  script_summary("Check for the version of Sun Java JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_require_keys("Sun/Java/JRE/Linux/Ver");
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

# Get KB for JRE Version On Linux
jreVer = get_kb_item("Sun/Java/JRE/Linux/Ver");

if(jreVer)
{
  jreVer = ereg_replace(pattern:"_", string:jreVer, replace: ".");
  jreVer = ereg_replace(pattern:"-b[0-9][0-9]", string:jreVer, replace:"");

  # Check for 1.6 < 1.6.0_15 (6 Update 15)
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.14")){
    security_hole(0);
  }
}
