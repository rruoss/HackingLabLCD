# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2006_045_09.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New xpdf packages are available for Slackware 9.0, 9.1, 10.0, 10.1, 10.2,
and -current to fix security issues.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2006-045-09.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-045-09";
                                                                                
if(description)
{
 script_id(56293);
 if(NASL_LEVEL>=2191) {
     script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628", "CVE-2006-0301");
 } else {
     script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");
 }
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$");
 name = "Slackware Advisory SSA:2006-045-09 xpdf ";
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

 script_summary("Slackware Advisory SSA:2006-045-09 xpdf");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/slackpack");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-slack.inc");
vuln = 0;
if(isslkpkgvuln(pkg:"xpdf", ver:"3.01-i386-3", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.01-i486-3", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.01-i486-3", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.01-i486-3a", rls:"SLK10.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"xpdf", ver:"3.01-i486-3", rls:"SLK10.2")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}