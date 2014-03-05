###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_reader_mult_dos_vuln_jun09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Foxit Reader Multiple Denial of Service Vulnerabilities - Jun09
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
tag_impact = "Successful exploitation will let attacker execute arbitrary code or crash an
  affected application.
  Impact Level: Application";
tag_affected = "Foxit Reader 3.0 before Build 1817 and JPEG2000/JBIG2 Decoder
  before 2.0.2009.616.";
tag_insight = "Multiple errors exist in the Foxit JPEG2000/JBIG2 Decoder add-on.
  - An error occures while processing a negative value for the stream offset
    in a JPX stream.
  - A fatal error while decoding JPX header which results in a subsequent
    invalid address access.";
tag_solution = "Upgrade to the latest version.
  http://www.foxitsoftware.com/downloads/";
tag_summary = "The host is installed with Foxit Reader and is prone to
  multiple Denial of Service vulnerabilities.";

if(description)
{
  script_id(900683);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0690", "CVE-2009-0691");
  script_bugtraq_id(35442, 35443);
  script_name("Foxit Reader Multiple Denial of Service Vulnerabilities - Jun09");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35512");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1640");
  script_xref(name : "URL" , value : "http://www.foxitsoftware.com/pdf/reader/security.htm#0602");

  script_description(desc);
  script_summary("Check for the version of Foxit Reader, fxdecod1.dll");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_foxit_reader_detect.nasl");
  script_require_keys("Foxit/Reader/Ver");
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

foxVer = get_kb_item("Foxit/Reader/Ver");

if(version_in_range(version:foxVer,test_version:"3.0" ,test_version2:"3.0.2009.1817"))
{
  foxitPath = registry_get_sz(key:"SOFTWARE\Foxit Software\Foxit Reader",
                                 item:"InstallPath");
  if(foxitPath)
  {
    foxitPath = foxitPath + "fxdecod1.dll";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:foxitPath);
    file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:foxitPath);
    fxdecodVer = GetVer(share:share, file:file);
    if((fxdecodVer) &&
      (version_is_less(version:fxdecodVer,test_version:"2.0.2009.616"))){
      security_hole(0);
    }
  }
}
