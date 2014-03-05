# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2009_176_01.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New seamonkey packages are available for Slackware 11.0, 12.0, 12.1, 12.2,
and -current to fix security issues.

More details about the issues may be found on the Mozilla web site:

http://www.mozilla.org/security/known-vulnerabilities/seamonkey11.html";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2009-176-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-176-01";
                                                                                
if(description)
{
 script_id(64317);
 script_version("$");
 script_cve_id("CVE-2009-1307", "CVE-2009-1311", "CVE-2009-1392", "CVE-2009-1832",
               "CVE-2009-1833", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1838",
               "CVE-2009-1841", "CVE-2009-2210");
 script_bugtraq_id(34656, 35370, 35326, 35371, 35391, 35380, 35461);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "Slackware Advisory SSA:2009-176-01 seamonkey ";
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

 script_summary("Slackware Advisory SSA:2009-176-01 seamonkey");

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
if(isslkpkgvuln(pkg:"seamonkey", ver:"1.1.17-i486-1_slack11.0", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"seamonkey", ver:"1.1.17-i486-1_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"seamonkey", ver:"1.1.17-i486-1_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"seamonkey", ver:"1.1.17-i486-1_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}