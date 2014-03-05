# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2007_316_01.nasl 18 2013-10-27 14:14:13Z jan $
# Description: Auto-generated from the corresponding slackware advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, and -current.  New poppler packages are available for Slackware 12.0
and -current.  New koffice packages are available for Slackware 11.0, 12.0,
and -current.  New kdegraphics packages are available for Slackware 10.2,
11.0, 12.0, and -current.

These updated packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through the
use of a malformed PDF document.  It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF.

These advisories and CVE entries cover the bugs:
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4352
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5392
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5393
http://www.kde.org/info/security/advisory-20071107-1.txt";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2007-316-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2007-316-01";
                                                                                
if(description)
{
 script_id(59020);
 script_cve_id("CVE-2007-3387", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$");
 name = "Slackware Advisory SSA:2007-316-01 xpdf/poppler/koffice/kdegraphics ";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution + "

";

 script_description(desc);

 script_summary("Slackware Advisory SSA:2007-316-01 xpdf/poppler/koffice/kdegraphics");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/slackpack");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack9.1", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.0", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.1", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.4.2-i486-3_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack10.2", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.4-i486-2_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"koffice", ver:"1.5.2-i486-5_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kdegraphics", ver:"3.5.7-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"poppler", ver:"0.6.2-i486-1_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"koffice", ver:"1.6.3-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.02pl2-i486-1_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
