# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2008_191_01.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New mozilla-firefox packages are available for Slackware 10.2, 11.0,
12.0, and 12.1 to fix security issues.

More details about the issues may be found on the Mozilla site:

http://www.mozilla.org/projects/security/known-vulnerabilities.html#firefox";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2008-191-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2008-191-01";
                                                                                
if(description)
{
 script_id(61465);
 script_version("$");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Slackware Advisory SSA:2008-191-01 mozilla-firefox ";
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

 script_summary("Slackware Advisory SSA:2008-191-01 mozilla-firefox");

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
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15-i686-1", rls:"SLK10.2")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15-i686-1", rls:"SLK11.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15-i686-1", rls:"SLK12.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.15-i686-1", rls:"SLK12.1")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
