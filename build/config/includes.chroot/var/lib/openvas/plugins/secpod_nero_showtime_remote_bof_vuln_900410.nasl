##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nero_showtime_remote_bof_vuln_900410.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Nero ShowTime 'm3u' File Remote Buffer Overflow Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application.
  Impact Level: Application";
tag_affected = "Nero ShowTime 5.0.15.0 and prior on all Windows platforms.";
tag_insight = "This error is due to inadequate boundary checks on user supplied input.";
tag_solution = "Solution/Patch not available as on 08th December, 2008.";
tag_summary = "This host is installed with Nero Showtime and is prone to
  'm3u' File Remote Buffer Overflow Vulnerability.";

if(description)
{
  script_id(900410);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_cve_id("CVE-2008-7079");
 script_bugtraq_id(32446);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Nero ShowTime 'm3u' File Remote Buffer Overflow Vulnerability");
  script_summary("Check for vulnerable version of Nero Showtime");
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

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7207");
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/32850");

  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

neroExe = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\App Paths\ShowTime.exe",
                          item:"Path");
if(neroExe)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:neroExe);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:neroExe);
  showtime = file + "ShowTime.exe";
  showtime = GetVer(file:showtime, share:share);
  {
    #Grep for Nero ShowTime 5.0.15.0 and prior.
    pattern = "^([0-4]\..*|5\.0(\.[0-9](\..*)?|\.1[0-4](\..*)?|\.15(\.0)?)?)";
    if(egrep(pattern:pattern,string:showtime)){
      security_hole(0);
    }
  }
}
