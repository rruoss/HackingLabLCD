###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ctorrent_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# CTorrent/Enhanced CTorrent Buffer Overflow Vulnerability
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
tag_impact = "Attackers can exploit this issue by execute arbitrary code via specially
  crafted torrent files and can cause denial of service.
  Impact Level: System/Application";
tag_affected = "CTorrent version 1.3.4 on Linux.
  Enhanced CTorrent version 3.3.2 and prior on Linux.";
tag_insight = "A stack based buffer overflow is due to a boundary error within the
  function 'btFiles::BuildFromMI()' in btfiles.cpp while processing torrent
  files containing a long path.";
tag_solution = "No solution or patch is available as of 27th May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.rahul.net/dholmes/ctorrent/";
tag_summary = "The host is installed with CTorrent/Enhanced CTorrent and is prone
  to Buffer Overflow Vulnerability.";

if(description)
{
  script_id(900557);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1759");
  script_bugtraq_id(34584);
  script_name("CTorrent/Enhanced CTorrent Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34752");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8470");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49959");

  script_description(desc);
  script_summary("Check for the Version of CTorrent/Enhanced CTorrent");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ctorrent_detect.nasl");
  script_require_keys("CTorrent/Ver", "Enhanced/CTorrent/Ver");
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

ctorrentVer = get_kb_item("CTorrent/Ver");
if(ctorrentVer != NULL)
{
  if(version_is_equal(version:ctorrentVer, test_version:"1.3.4"))
  {
    security_hole(0);
    exit(0);
  }
}

ectorrentVer = get_kb_item("Enhanced/CTorrent/Ver");
if(ectorrentVer != NULL)
{
  if(version_is_less_equal(version:ectorrentVer, test_version:"3.3.2")){
    security_hole(0);
  }
}
