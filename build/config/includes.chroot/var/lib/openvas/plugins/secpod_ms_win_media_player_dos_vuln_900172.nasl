##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_win_media_player_dos_vuln_900172.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Microsoft Windows Media Player 'MIDI' or 'DAT' File DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "This host is installed with Windows Media Player and is prone to
  denial of service vulnerability.

  The vulnerability is due to error in handling 'MIDI' or 'DAT' file,
  related to 'MThd Header Parsing'.";

tag_impact = "Successful exploitation will cause denial of service.
  Impact Level: Application";
tag_affected = "Microsoft Windows Media Player versions 9.x, 10.x and 11.x";
tag_solution = "No solution or patch is available as of 05th November, 2008.";

if(description)
{
  script_id(900172);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-11 15:58:44 +0100 (Tue, 11 Nov 2008)");
  script_bugtraq_id(32077);
  script_cve_id("CVE-2008-4927");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Windows Media Player 'MIDI' or 'DAT' File DoS Vulnerability");
  script_summary("Check for vulnerable version of Windows Media Player");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-4927");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/data/vulnerabilities/exploits/32077.py");

  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl",
                      "secpod_ms_win_media_player_detect_900173.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Check the versions 9.x , 10.x and 11.x
if(get_kb_item("Win/MediaPlayer/Ver") =~ "^(9|1[01])\..*$"){
  security_warning(0);
}
