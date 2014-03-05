###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: secpod_ms_win_media_player_dos_vuln_mar10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Media Player '.AVI' File DOS Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "This host is installed with windows media player and is prone to
  Denial Of Service vulnerability.

  Vulnerabilities Insight:
  The flaw is due to error in '.avi' file, which fails to perform colorspace
  conversion properly, and causes denial of service (memory corruption).";

tag_impact = "Successful exploitation will allow attackers to cause a denial of service
  or possibly execute arbitrary code via a crafted message.
  Impact Level: Application";
tag_affected = "Microsoft Windows Media Player versions 11.x";
tag_solution = "No solution or patch is available as of 26th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/";

if(description)
{
  script_id(900757);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1042");
  script_bugtraq_id(38790);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");

  script_name("Microsoft Windows Media Player '.AVI' File DOS Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38790");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2010-1042");

  script_description(desc);
  script_summary("Check for the version of Windows media player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_ms_win_media_player_detect_900173.nasl");
  script_require_keys("Win/MediaPlayer/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

mediaVer = get_kb_item("Win/MediaPlayer/Ver");
if(mediaVer != NULL)
{
  # Check if the version is 11.x
   if(version_in_range(version:mediaVer, test_version:"11", test_version2:"11.0.6000.6324")){
     security_warning(0);
   }
}
