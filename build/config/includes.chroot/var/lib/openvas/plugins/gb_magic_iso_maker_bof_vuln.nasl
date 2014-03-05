###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magic_iso_maker_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Magic ISO Maker Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the application and can cause Heap Overflow.

  Impact level: Application";

tag_affected = "Magic ISO Maker version 5.5 build 274 and prior.";
tag_insight = "This flaw is due to inadequate boundary check while processing 'CCD'
  image files.";
tag_solution = "No solution or patch is available as of 09th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  updates refer, http://www.magiciso.com/download.htm";
tag_summary = "This host is running Magic ISO Maker and is prone to Heap-Based
  Buffer Overflow Vulnerability.";

if(description)
{
  script_id(800273);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1257");
  script_name("Magic ISO Maker Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34595");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8343");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0940");

  script_description(desc);
  script_summary("Check for the version of Magic ISO Maker");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_magic_iso_maker_detect.nasl");
  script_require_keys("MagicISOMaker/Ver");
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

magicVer = get_kb_item("MagicISOMaker/Ver");
if(!magicVer){
  exit(0);
}

# Grep for Magic ISO maker version 5.5.0274 or prior.
if(version_is_less_equal(version:magicVer, test_version:"5.5.0274")){
  security_hole(0);
}
