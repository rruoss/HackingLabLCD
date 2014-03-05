##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_rtcp_remote_dos_vuln_900404.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Microsoft Windows RTCP Unspecified Remote DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will crash the application.
  Impact Level: Application";
tag_affected = "Microsoft Windows Live Messenger version 8.5.1302.1018 and prior.";
tag_insight = "The vulnerability is due to error in the 'RTCP' or
  'Real-time Transport Control Protocol' receiver report packet handling.";
tag_solution = "No solution or patch is available as of 26th November, 2008.";
tag_summary = "This host is installed with Microsoft Live Messenger and is prone to
  remote Denial of Service vulnerability.";

if(description)
{
  script_id(900404);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5179");
 script_bugtraq_id(32341);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Microsoft Windows RTCP Unspecified Remote DoS Vulnerability");
  script_summary("Check for vulnerable version of Live Messenger");
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
  script_xref(name : "URL" , value : "http://www.voipshield.com/research-details.php?id=132");

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

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(!registry_key_exists(key:key)) {
  exit(0);
}

entries = registry_enum_keys(key:key);
if(entries == NULL){
  exit(0);
}

foreach item (entries)
{
  if("Windows Live Messenger" >< registry_get_sz(key:key + item, item:"DisplayName"))
  {
    # Grep or versions Windows Live Messenger version 8.5.1302.1018 and prior.
    if((egrep(pattern:"^([0-7]\..*|8\.[0-4](\..*)?|8\.5(\.([0-9]?[0-9]?[0-9]" +
                      "|1[0-2]?[0-9]?[0-9]?|130[01])(\..*)?|\.1302)?(\.[0-9]" +
                      "?[0-9]?[0-9]|\.100[0-9]|\.101[0-8])?)?$",
              string:registry_get_sz(key:key + item, item:"DisplayVersion")))){
      security_warning(0);
    }
  }
}
