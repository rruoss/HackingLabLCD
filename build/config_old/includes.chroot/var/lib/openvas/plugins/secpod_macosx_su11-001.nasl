###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_macosx_su11-001.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mac OS X v10.6.6 Multiple Vulnerabilities (2011-001)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions or cause a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "X11,
  ATS,
  PHP,
  HFS,
  Ruby,
  Samba,
  bzip2,
  Kernel,
  AirPort,
  Apache,
  ClamAV,
  Mailman,
  Libinfo,
  libxml,
  ImageIO,
  Kerberos,
  CoreText,
  Terminal,
  Installer,
  QuickLook,
  QuickTime,
  Image RAW,
  Subversion,
  CarbonCore,
  AppleScript,
  File Quarantine";
tag_insight = "For more information on the vulnerabilities refer to the links below.";
tag_solution = "Upgrade to Mac OS X 10.6.7 or Run Mac Updates and update the Security
  Update 2011-001
  For updates refer to http://support.apple.com/kb/HT1222";
tag_summary = "This host is missing an important security update according to
  Mac OS X 10.6.6 Update/Mac OS X Security Update 2011-001.";

if(description)
{
  script_id(902470);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-0172", "CVE-2010-1452", "CVE-2010-2068", "CVE-2011-0173",
                "CVE-2011-0174", "CVE-2011-0175", "CVE-2011-0176", "CVE-2011-0177",
                "CVE-2010-0405", "CVE-2011-0178", "CVE-2010-3434", "CVE-2010-4260",
                "CVE-2010-4261", "CVE-2010-4479", "CVE-2011-0179", "CVE-2011-0180",
                "CVE-2011-0170", "CVE-2011-0181", "CVE-2011-0191", "CVE-2011-0192",
                "CVE-2011-0194", "CVE-2011-0193", "CVE-2011-0190", "CVE-2010-1323",
                "CVE-2010-1324", "CVE-2010-4020", "CVE-2010-4021", "CVE-2011-0182",
                "CVE-2011-0183", "CVE-2010-4008", "CVE-2010-4494", "CVE-2010-3089",
                "CVE-2006-7243", "CVE-2010-2950", "CVE-2010-3709", "CVE-2010-3710",
                "CVE-2010-4409", "CVE-2010-3436", "CVE-2010-3709", "CVE-2010-4150",
                "CVE-2011-0184", "CVE-2011-1417", "CVE-2011-0186", "CVE-2010-4009",
                "CVE-2010-3801", "CVE-2011-0187", "CVE-2010-3802", "CVE-2011-0188",
                "CVE-2010-3069", "CVE-2010-3315", "CVE-2011-0189", "CVE-2010-3814",
                "CVE-2010-3855", "CVE-2010-3870", "CVE-2010-4150");
  script_bugtraq_id(46988, 41963, 40827, 46984, 46987, 46991, 46971, 46994, 43331,
                    46989, 43555, 45152, 45152, 45152, 46993, 46982, 46659, 46996,
                    46657, 46658, 46973, 46972, 47023, 45118, 45116, 45117, 45122,
                    46997, 46990, 44779, 45617, 43187, 44951, 44718, 43926, 45119,
                    44723, 44718, 44980, 46965, 46832, 46995, 45241, 45240, 46992,
                    45239, 46966, 43212, 43678, 44643, 44214, 44605, 44980);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mac OS X v10.6.6 Multiple Vulnerabilities (2011-001)");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT1222");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce//2011//Mar/msg00006.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
  script_summary("Checks for existence of Mac OS X 10.6.6 Update/Mac OS X Security Update 2011-001");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("pkg-lib-macosx.inc");
include("version_func.inc");

## Get the OS name
osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

## Get the OS Version
osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
 exit(0);
}

## Check for the Mac OS X and Mac OS X Server
if("Mac OS X" >< osName || "Mac OS X Server" >< osName)
{
  ## Check the affected OS versions
  if(version_is_less_equal(version:osVer, test_version:"10.5.8") ||
     version_in_range(version:osVer, test_version:"10.6", test_version2:"10.6.6"))
  {
    ## Check for the security update 2011.001
    if(isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2011.001"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
