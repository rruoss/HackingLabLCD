###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_mem_crptn_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Tor Unspecified Remote Memory Corruption Vulnerability (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "A remote user could execute arbitrary code on the target system and can
  cause denial-of-service or compromise a vulnerable system.

  Impact level: Application";

tag_affected = "Tor version prior to 0.2.0.33 on Windows.";
tag_insight = "Due to unknown impact, remote attackers can trigger heap corruption on
  the application.";
tag_solution = "Upgrade to version 0.2.0.33 or later
  http://www.torproject.org/download.html.en";
tag_summary = "This host is installed with Tor and is prone to unspecified remote
  Memory Corruption vulnerability.";

if(description)
{
  script_id(800352);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-06 13:48:17 +0100 (Fri, 06 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0414");
  script_bugtraq_id(33399);
  script_name("Tor Unspecified Remote Memory Corruption Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33635");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33677");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jan/1021633.html");
  script_xref(name : "URL" , value : "http://blog.torproject.org/blog/tor-0.2.0.33-stable-released");

  script_description(desc);
  script_summary("Check for the version of Tor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

torVer = get_kb_item("Tor/Win/Ver");
if(torVer != NULL)
{
  # Grep for version prior to 0.2.0.33
  if(version_is_less(version:torVer, test_version:"0.2.0.33")){
    security_hole(0);
  }
}
