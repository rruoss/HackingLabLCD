###################################################################
# OpenVAS Vulnerability Test
#
# Mac OS X 10.5.8 Update / Mac OS X Security Update 2009-003
#
# LSS-NVT-2010-025
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_solution = "Update your Mac OS X operating system.

 For more information see:
 http://support.apple.com/kb/HT3757";

tag_summary = "The remote host is missing Mac OS X 10.5.8 Update / Mac OS X Security Update 2009-003.
 One or more of the following components are affected:

 bzip2
 CFNetwork
 ColorSync
 CoreTypes
 Dock
 Image RAW
 ImageIO
 Kernel
 launchd
 Login Window
 MobileMe
 Networking
 XQuery";


if(description)
{
 script_id(102036);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-12 14:48:44 +0200 (Wed, 12 May 2010)");
 script_cve_id("CVE-2008-1372","CVE-2009-1723","CVE-2009-1726","CVE-2009-1727","CVE-2009-0151","CVE-2009-1728","CVE-2009-1722","CVE-2009-1721","CVE-2009-1720","CVE-2009-2188","CVE-2009-0040","CVE-2009-1235","CVE-2009-2190","CVE-2009-2191","CVE-2009-2192","CVE-2009-2193","CVE-2009-2194","CVE-2008-0674");
 script_name("Mac OS X 10.5.8 Update / Mac OS X Security Update 2009-003");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_summary("Checks for existence of Mac OS X 10.5.8 Update / Mac OS X Security Update 2009-003");
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2010 LSS");
 script_family("Mac OS X Local Security Checks");
 script_require_ports("Services/ssh", 22);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/osx_name","ssh/login/osx_version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("pkg-lib-macosx.inc");
include("version_func.inc");

ssh_osx_name = get_kb_item("ssh/login/osx_name");
if (!ssh_osx_name) exit (0);

ssh_osx_ver = get_kb_item("ssh/login/osx_version");
if (!ssh_osx_ver) exit (0);

ssh_osx_rls = ssh_osx_name + ' ' + ssh_osx_ver;

pkg_for_ver = make_list("Mac OS X 10.4.11","Mac OS X Server 10.4.11","Mac OS X 10.5.7","Mac OS X Server 10.5.7");

if (rlsnotsupported(rls:ssh_osx_rls, list:pkg_for_ver)) { security_hole(0); exit(0);}

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X 10.4.11"))) { security_hole(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.003"))) { security_hole(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.4.11")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:osx_ver(ver:"Mac OS X Server 10.4.11"))) { security_hole(0); exit(0);}
    else if ((ssh_osx_ver==osx_ver(ver:"Mac OS X Server 10.4.11")) && (isosxpkgvuln(fixed:"com.apple.pkg.update.security.", diff:"2009.003"))) { security_hole(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.5.7")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.8")) { security_hole(0); exit(0); }
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.5.7")) {
    if (version_is_less(version:osx_ver(ver:ssh_osx_rls), test_version:"10.5.8")) { security_hole(0); exit(0); }
}
