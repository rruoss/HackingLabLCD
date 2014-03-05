###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kvirc_arg_inj_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# KVIrc URI Handler Argument Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary commands.
  Impact Level: Application";
tag_affected = "KVirc version 3.4.2 and prior on Windows";
tag_insight = "The flaw is due to an improper validation of user supplied input, which
  can be exploited by persuading a victim to open a specially-crafted 'irc:///',
  'irc6:///', 'ircs:///', or 'ircs6:///' URI.";
tag_solution = "No solution or patch is available as of 28th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.kvirc.net/?lang=en";
tag_summary = "This host has KVIrc installed and is prone to Argument Injection
  vulnerability.";

if(description)
{
  script_id(901011);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-7070");
  script_bugtraq_id(32410);
  script_name("KVIrc URI Handler Argument Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7181");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46779");

  script_description(desc);
  script_summary("Check for the version of KVIrc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_kvirc_detect_win.nasl");
  script_require_keys("Kvirc/Win/Ver");
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

# Get for KVIrc Version
kvircVer = get_kb_item("Kvirc/Win/Ver");

if(kvircVer != NULL)
{
  # Check for KVirc version <= 3.4.2
  if(version_is_less_equal(version:kvircVer, test_version:"3.4.2")){
    security_hole(0);
  }
}
