##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_bitdefender_pdf_parsing_dos_vuln_900180.nasl 16 2013-10-27 13:09:52Z jan $
# Description: BitDefender 'pdf.xmd' Module PDF Parsing Remote DoS Vulnerability
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
tag_summary = "This host is installed with BitDefender Internet Security and AntiVirus
  and is prone to denial of service vulnerability.

  The flaw is due to boundary error in 'pdf.xmd' module when parsing of
  data encoded using 'FlateDecode' and 'ASCIIHexDecode' filters. This can be
  exploited to cause a memory corruption during execution of 'bdc.exe'.";

tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can deny the service to the legitimate user.
  Impact Level: Application";
tag_affected = "BitDefender Internet Security and Antivirus version 10 and prior on Windows";
tag_solution = "Update to higher version
  http://www.bitdefender.com/site/Downloads/";

if(description)
{
  script_id(900180);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5409");
 script_bugtraq_id(32396);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("BitDefender 'pdf.xmd' Module PDF Parsing Remote DoS Vulnerability");
  script_summary("Check for vulnerable version of BitDefender");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7178");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32789");

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

bitDef = "SOFTWARE\BitDefender\About\";
bitName = registry_get_sz(key:bitDef, item:"ProductName");
if(("BitDefender Internet Security" >< bitName) ||
   ("BitDefender Antivirus" >< bitName))
{
  bitVer = registry_get_sz(key:bitDef, item:"ProductVersion");
  # Check the versions 10 and prior
  if(egrep(pattern:"10(\..*)", string:bitVer)){
    security_hole(0);
  }
}