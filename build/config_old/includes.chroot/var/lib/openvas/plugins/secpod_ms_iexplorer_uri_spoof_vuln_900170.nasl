##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iexplorer_uri_spoof_vuln_900170.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Microsoft iExplorer '&NBSP;' Address Bar URI Spoofing Vulnerability
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
tag_summary = "This host is installed with Microsoft Internet Explorer and is prone
  to URI spoofing vulnerability.

  The flaw is exists due to failure to adequately handle specific combination
  of the non-breaking space character like '&NBSP;'.";

tag_impact = "Attacker may leverage this issue to spoof the source URI of a site which leads
  to false sense of trust.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer versions 6.0 SP1 and prior";
tag_solution = "No solution or patch is available as of 31st October, 2008.";

if(description)
{
  script_id(900170);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-05 06:52:23 +0100 (Wed, 05 Nov 2008)");
  script_bugtraq_id(31960);
  script_cve_id("CVE-2008-4787");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("Microsoft iExplorer '&NBSP;' Address Bar URI Spoofing Vulnerability");
  script_summary("Check for vulnerable version of Microsoft Internet Explorer");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?execution");

  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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

key = "SOFTWARE\Microsoft\Internet Explorer";
iExpVer = registry_get_sz(key:key , item:"Version");
if(!iExpVer){
  iExpVer = registry_get_sz(key:key, item:"W2kVersion");
  if(!iExpVer){
    exit(0);
  }
}

# Grep for version 6.0 x
if(ereg(pattern:"^6\.0", string:iExpVer)){
  security_hole(0);
}
