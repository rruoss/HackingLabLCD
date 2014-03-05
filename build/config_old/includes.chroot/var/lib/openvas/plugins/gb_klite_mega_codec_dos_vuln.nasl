###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_klite_mega_codec_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# K-Lite Mega Codec Pack vsfilter.dll Denial Of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "K-Lite Mega Codec Pack 3.5.7.0 and earlier on Windows (Any).

  *****
  NOTE : Some Higher Versions of K-Lite Mega Codec Pack seems to be
  also vulnerable.
  *****";

tag_impact = "By tricking a user to interact with a specially crafted .flv file,
  attackers can cause Windows Explorer to crash.
  Impact Level: System";
tag_insight = "The flaw is due to error in vsfilter.dll file, which fails to properly
  validate the input data.";
tag_solution = "No solution or patch is available as of 19th November, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.codecguide.com/download_mega.htm";
tag_summary = "This host is installed with K-Lite Mega Codec Pack and is prone to
  Denial Of Service Vulnerability.";

if(description)
{
  script_id(800139);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5072");
  script_bugtraq_id(31400);
  script_name("K-Lite Mega Codec Pack vsfilter.dll Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6565");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45446");

  script_description(desc);
  script_summary("Check for the Version of K-Lite Mega Codec Pack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

klitePath = registry_get_sz(key:"SOFTWARE\KLCodecPack", item:"installdir");
if(!klitePath){
  exit(0);
}

klitePath += "\Filters\vsfilter.dll";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:klitePath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:klitePath);

kliteVer = GetVer(file:file, share:share);
if(!kliteVer){
  exit(0);
}

# Check for K-Lite Mega Codec Pack File Version (vsfilter.dll) < 1.0.1.5
if(version_is_less(version:kliteVer, test_version:"1.0.1.5")){
  security_warning(0);
}
