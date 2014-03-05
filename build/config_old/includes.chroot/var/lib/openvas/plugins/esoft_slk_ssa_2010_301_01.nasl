# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2010_301_01.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New glibc packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
and -current to fix a security issue.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2010-301-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2010-301-01";
                                                                                
if(description)
{
 script_id(68470);
 script_cve_id("CVE-2010-3856");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 18 $");
 script_name("Slackware Advisory SSA:2010-301-01 glibc ");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution + "

";

 script_description(desc);

 script_summary("Slackware Advisory SSA:2010-301-01 glibc ");

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
if(isslkpkgvuln(pkg:"glibc", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-i18n", ver:"2.5-noarch-6_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-profile", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-solibs", ver:"2.5-i486-6_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.5-noarch-9_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-i18n", ver:"2.7-noarch-12_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-profile", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-solibs", ver:"2.7-i486-12_slack12.1", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.7-noarch-12_slack12.0", rls:"SLK12.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-i18n", ver:"2.7-noarch-19_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-profile", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-solibs", ver:"2.7-i486-19_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.7-noarch-19_slack12.2", rls:"SLK12.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-i18n", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-profile", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-solibs", ver:"2.9-i486-5_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.9-noarch-5_slack13.0", rls:"SLK13.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-i18n", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-profile", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-solibs", ver:"2.11.1-i486-5_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"glibc-zoneinfo", ver:"2.11.1-noarch-5_slack13.1", rls:"SLK13.1")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
