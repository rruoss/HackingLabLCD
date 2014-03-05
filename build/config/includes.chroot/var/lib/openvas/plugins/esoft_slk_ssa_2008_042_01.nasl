# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2008_042_01.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New kernel packages are available for Slackware 12.0, and -current to
fix a local root exploit.

More details about this issue may be found in the Common
Vulnerabilities and Exposures (CVE) database:

http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0010
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0163
http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0600";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2008-042-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2008-042-01";
                                                                                
if(description)
{
 script_id(60390);
 script_cve_id("CVE-2008-0010", "CVE-2008-0163", "CVE-2008-0600");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2008-042-01 kernel exploit fix ";
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

 script_summary("Slackware Advisory SSA:2008-042-01 kernel exploit fix");

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
if(isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.21.5-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.21.5_smp-i686-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.21.5-i486-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"kernel-huge-smp", ver:"2.6.21.5_smp-i686-2_slack12.0", rls:"SLK12.0")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
