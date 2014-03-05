###################################################################
# OpenVAS Vulnerability Test
#
# Safari 4.0.5 Update
#
# LSS-NVT-2010-010
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
tag_solution = "Update Safari to newest version.

 For more information see:
 http://support.apple.com/kb/HT4070";

tag_summary = "Installed version of Safari on remote host is older than 4.0.5 and
 contains security vulnerabilities.
 One or more of the following components are affected:

 PubSub
 WebKit";


if(description)
{
 script_id(102022);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-06 10:41:02 +0200 (Tue, 06 Apr 2010)");
 script_name("Safari 4.0.5 Update");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_summary("Checks for Safari version");
 script_category(ACT_GATHER_INFO);
 script_cve_id("CVE-2010-0044","CVE-2010-0046","CVE-2010-0047","CVE-2010-0048","CVE-2010-0049","CVE-2010-0050","CVE-2010-0051","CVE-2010-0052","CVE-2010-0053","CVE-2010-0054");
 script_copyright("Copyright (C) 2010 LSS");
 script_family("Mac OS X Local Security Checks");
 script_require_ports("Services/ssh", 22);
 script_dependencies("macosx_safari_detect.nasl");
 script_mandatory_keys("AppleSafari/MacOSX/Version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

include("version_func.inc");

ver = get_kb_item("AppleSafari/MacOSX/Version");

if (!ver) {exit(0);}

if (version_is_less(version:ver, test_version:"4.0.5")) {
    security_hole(0);
}
