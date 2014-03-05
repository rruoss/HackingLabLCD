# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2005_255_02.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "New util-linux packages are available for Slackware 8.1, 9.0, 9.1, 10.0,
10.1, and -current to fix a security issue with umount.  A bug in the
'-r' option could allow flags in /etc/fstab to be improperly dropped
on user-mountable volumes, allowing a user to gain root privileges.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2005-255-01.";

tag_solution = "http://www.securityfocus.com/archive/1/410333
https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-255-01";
                                                                                
if(description)
{
 script_id(55377);
 script_bugtraq_id(14816);
 script_cve_id("CVE-2005-2876");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2005-255-02 util-linux umount";
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

 script_summary("Slackware Advisory SSA:2005-255-02 util-linux umount");

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
if(isslkpkgvuln(pkg:"util-linux", ver:"2.11r-i386-2", rls:"SLK8.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"util-linux", ver:"2.11z-i386-2", rls:"SLK9.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"util-linux", ver:"2.12-i486-2", rls:"SLK9.1")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"util-linux", ver:"2.12a-i486-2", rls:"SLK10.0")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"util-linux", ver:"2.12p-i486-2", rls:"SLK10.1")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}