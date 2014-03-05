# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2012_300_01.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory SSA:2012-300-01
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
tag_insight = "New mozilla-firefox packages are available for Slackware 13.37, 14.0,
and -current to fix a security issue.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2012-300-01.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2012-300-01";
                                                                                
if(description)
{
 script_id(72539);
 script_version("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-10-29 10:21:49 -0400 (Mon, 29 Oct 2012)");
 script_name("Slackware Advisory SSA:2012-300-01 mozilla-firefox ");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Slackware Advisory SSA:2012-300-01 mozilla-firefox ");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Slackware Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_require_keys("ssh/login/slackpack");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:slackware_linux", "login/SSH/success", "ssh/login/slackpack");
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
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"16.0.2-i486-1_slack13.37", rls:"SLK13.37")) {
    vuln = 1;
}
if(isslkpkgvuln(pkg:"mozilla-firefox", ver:"16.0.2-i486-1_slack14.0", rls:"SLK14.0")) {
    vuln = 1;
}

if(vuln) {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}