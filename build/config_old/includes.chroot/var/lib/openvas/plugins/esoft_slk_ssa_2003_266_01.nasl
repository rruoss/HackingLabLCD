# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2003_266_01.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "Upgraded OpenSSH 3.7.1p2 packages are available for Slackware 8.1,
9.0 and -current.  This fixes security problems with PAM
authentication.  It also includes several code cleanups from Solar
Designer.

Slackware is not vulnerable to the PAM problem, and it is not
believed that any of the other code cleanups fix exploitable
security problems, not nevertheless sites may wish to upgrade.

These are some of the more interesting entries from OpenSSH's
ChangeLog so you can be the judge:

[buffer.c]
protect against double free; #660;  zardoz at users.sf.net
- markus@cvs.openbsd.org 2003/09/18 08:49:45
[deattack.c misc.c session.c ssh-agent.c]
more buffer allocation fixes; from Solar Designer; CVE-2003-0682;
ok millert@
- (djm) Bug #676: Fix PAM stack corruption
- (djm) Fix bad free() in PAM code";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2003-266-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-266-01";
                                                                                
if(description)
{
 script_id(53964);
 script_cve_id("CVE-2003-0682");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2003-266-01 New OpenSSH packages ";
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

 script_summary("Slackware Advisory SSA:2003-266-01 New OpenSSH packages");

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
if(isslkpkgvuln(pkg:"openssh", ver:"3.7.1p2-i386-1", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"openssh", ver:"3.7.1p2-i386-1", rls:"SLK9.0")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
