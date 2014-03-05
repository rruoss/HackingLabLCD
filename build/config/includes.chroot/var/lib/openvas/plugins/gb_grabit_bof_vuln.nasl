###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_grabit_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# GrabIt Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker cause stack overflow by
  crafting an 'NZB' file containing an overly large string as DTD URI.

  Impact level: Application";

tag_affected = "GrabIt version 1.7.2 Beta 3 and prior.";
tag_insight = "This flaw is due to a boundary check error when processing the DOCTYPE
  declaration within '.NZB' files.";
tag_solution = "Upgrade to the latest version 1.7.2 Beta 4
  http://www.shemes.com/index.php?p=download";
tag_summary = "This host is installed with GrabIt and is prone to stack-based
  buffer overflow vulnerability.";

if(description)
{
  script_id(800713);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-18 09:37:31 +0200 (Mon, 18 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1586");
  script_bugtraq_id(34807);
  script_name("GrabIt Stack Based Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34893");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8612");
  script_xref(name : "URL" , value : "http://www.shemes.com/index.php?p=whatsnew");

  script_description(desc);
  script_summary("Check for the version of GrabIt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_grabit_detect.nasl");
  script_require_keys("GrabIt/Ver");
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

grabitVer = get_kb_item("GrabIt/Ver");
if(grabitVer == NULL){
  exit(0);
}

# Grep for GrabIt version 1.7.2 Beta 3 or prior.
if(version_is_less(version:grabitVer, test_version:"1.7.2.4")){
  security_hole(0);
}
