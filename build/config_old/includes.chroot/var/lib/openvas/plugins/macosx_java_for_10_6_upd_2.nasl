###################################################################
# OpenVAS Vulnerability Test
#
# Java for Mac OS X 10.6 Update 2
#
# LSS-NVT-2010-036
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
tag_solution = "Update your Java for Mac OS X.

 For more information see:
 http://support.apple.com/kb/HT4171";

tag_summary = "The remote host is missing Java for Mac OS X 10.6 Update 2.
 One or more of the following components are affected:

 Java";


if(description)
{
 script_id(102047);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-28 13:49:16 +0200 (Fri, 28 May 2010)");
 script_cve_id("CVE-2009-1105","CVE-2009-3555","CVE-2009-3910","CVE-2010-0082","CVE-2010-0084","CVE-2010-0085","CVE-2010-0087","CVE-2010-0088","CVE-2010-0089","CVE-2010-0090","CVE-2010-0091","CVE-2010-0092","CVE-2010-0093","CVE-2010-0094","CVE-2010-0095","CVE-2010-0837","CVE-2010-0838","CVE-2010-0840","CVE-2010-0841","CVE-2010-0842","CVE-2010-0843","CVE-2010-0844","CVE-2010-0846","CVE-2010-0847","CVE-2010-0848","CVE-2010-0849","CVE-2010-0886","CVE-2010-0887","CVE-2010-0538","CVE-2010-0539");
 script_name("Java for Mac OS X 10.6 Update 2");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_summary("Checks for existence of Java for Mac OS X 10.6 Update 2");
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

pkg_for_ver = make_list("Mac OS X 10.6.3","Mac OS X Server 10.6.3");

if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X 10.6.3")) {
	if (isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6Update", diff:"2")) { security_hole(0); exit(0);}
}
if (osx_rls_name(rls:ssh_osx_rls) == osx_rls_name(rls:"Mac OS X Server 10.6.3")) {
	if (isosxpkgvuln(fixed:"com.apple.pkg.JavaForMacOSX10.6Update", diff:"2")) { security_hole(0); exit(0);}
}
