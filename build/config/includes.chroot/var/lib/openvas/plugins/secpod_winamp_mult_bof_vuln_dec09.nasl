###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winamp_mult_bof_vuln_dec09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Winamp Module Decoder Plug-in Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Attacker may leverage this issue by executing arbitrary codes in the context
  of the affected application and can cause denial of service.
  Impact Level: System/Application";
tag_affected = "Winamp version prior to 5.57 on Windows.";
tag_insight = "Multiple flaws are due to:
  - Boundary errors in the Module Decoder Plug-in (IN_MOD.DLL) when parsing
    instrument definitions, samples or Ultratracker files.
  - An integer overflow error in the Module Decoder Plug-in when parsing crafted
    Oktalyzer PNG or JPEG Files.";
tag_solution = "Upgrade to the version 5.57,
  http://www.winamp.com/player";
tag_summary = "This host is installed with Winamp and is prone to multiple Buffer
  Overflow vulnerabilities.";

if(description)
{
  script_id(901085);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3995", "CVE-2009-3996", "CVE-2009-3997", "CVE-2009-4356");
  script_bugtraq_id(37374, 37387);
  script_name("Winamp Module Decoder Plug-in Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37495");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-56");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3575");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3576");
  script_xref(name : "URL" , value : "http://forums.winamp.com/showthread.php?threadid=315355");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/508528/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Winamp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_winamp_detect.nasl");
  script_require_keys("Winamp/Version");
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
include("version_func.inc");
include("secpod_smb_func.inc");

winampVer = get_kb_item("Winamp/Version");
if(!winampVer){
  exit(0);
}

# Check for version prior to 5.57 (5.5.7.2792)
if(version_is_less(version:winampVer, test_version:"5.5.7.2792"))
{
  winPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\winamp.exe", item:"Path");
  if(!winPath){
    exit(0);
  }

  winPath =  winPath + "\Plugins\IN_MOD.DLL";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:winPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:winPath);
  dllSize = get_file_size(share:share, file:file);
  if(dllSize){
    security_hole(0);
  }
}
