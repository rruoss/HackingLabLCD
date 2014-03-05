###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xvid_bof_vuln_jun09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Xvid Buffer Overflow Vulnerability (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Remote attackers may exploit this issue to cause multiple heap based buffer
  overflow, execute arbitrary code and may cause denial of service.
  Impact Level: System/Application";
tag_affected = "Xvid before 1.2.2 on Windows.";
tag_insight = "- Inadequate sanitation of user supplied data in 'decoder_iframe',
    'decoder_pframe' and 'decoder_bframe' fuctions in xvidcore/src/decoder.c
    and can be exploited by providing a crafted macroblock (aka MBlock) number
    in a video stream in a crafted movie file.
  - A boundary error in 'decoder_create' function n xvidcore/src/decoder.c
    can be exploited via vectors involving the DirectShow (aka DShow) frontend
    and improper handling of the XVID_ERR_MEMORY return code during processing
    of a crafted movie file";
tag_solution = "Upgrade to Xvid 1.2.2 or later
  http://www.xvid.org/";
tag_summary = "This host has Xvid installed, and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(800580);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-09 08:37:33 +0200 (Tue, 09 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0893", "CVE-2009-0894");
  script_bugtraq_id(35156, 35158);
  script_name("Xvid Buffer overflow Vulnerability (Win) - Jun09");
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
  script_summary("Check for the Version of Xvid");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_xvid_detect_win.nasl");
  script_require_keys("Xvid/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35274");
  script_xref(name : "URL" , value : "http://cvs.xvid.org/cvs/viewvc.cgi/xvidcore/src/decoder.c");
  script_xref(name : "URL" , value : "http://cvs.xvid.org/cvs/viewvc.cgi/xvidcore/src/decoder.c?r1=1.80&amp;r2=1.81");
  exit(0);
}


include("version_func.inc");

xvidVer = get_kb_item("Xvid/Win/Ver");
if(xvidVer == NULL){
  exit(0);
}

if(version_is_less(version:xvidVer, test_version:"1.2.2")){
  security_hole(0);
}
