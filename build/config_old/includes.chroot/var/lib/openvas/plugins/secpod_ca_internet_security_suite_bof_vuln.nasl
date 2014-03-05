###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_internet_security_suite_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CA Internet Security Suite Plus 'KmxSbx.sys' Buffer Overflow Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows execution of arbitrary code in the kernel.
  Impact Level: Application/System";
tag_affected = "CA Internet Security Suite Plus 2010";

tag_insight = "The flaw is due to an error in the 'KmxSbx.sys' kernel driver when
  processing IOCTLs and can be exploited to cause a buffer overflow via
  overly large data buffer sent to the 0x88000080 IOCTL.";
tag_solution = "No solution or patch is available as of 31st January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://shop.ca.com/ca/products/internetsecurity/internetsecurity_suite.asp";
tag_summary = "This host is installed with CA Internet Security Suite Plus and is
  prone to buffer overflow vulnerability.";

if(description)
{
  script_id(901177);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_cve_id("CVE-2010-4502");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("CA Internet Security Suite Plus 'KmxSbx.sys' Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42267");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15624");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024808");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3070");

  script_description(desc);
  script_summary("Check for the version of KmxSbx.sys");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows OS
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Application
if(!registry_key_exists(key:"SOFTWARE\ComputerAssociates")){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysPath = sysPath + "\system32\drivers\KmxSbx.sys";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath);

## Get Version from KmxSbx.sys file
sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

## Check for KmxSbx.sys version 6.2.0.22
if(version_is_equal(version:sysVer, test_version:"6.2.0.22")){
  security_hole(0);
}
