# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2003_141_06a.nasl 18 2013-10-27 14:14:13Z jan $
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
tag_insight = "NOTE:  The original advisory quotes a section of the Slackware ChangeLog
which had inadvertently reversed the options to quotacheck.  The correct
option to use is 'm'.  A corrected advisory follows:

An upgraded sysvinit package is available which fixes a problem with
the use of quotacheck in /etc/rc.d/rc.M.  The original version of
rc.M calls quotacheck like this:

echo 'Checking filesystem quotas:  /sbin/quotacheck -avugM'
/sbin/quotacheck -avugM

The 'M' option is wrong.  This causes the filesystem to be remounted,
and in the process any mount flags such as nosuid, nodev, noexec,
and the like, will be reset.  The correct option to use here is 'm',
which does not attempt to remount the partition:

echo 'Checking filesystem quotas:  /sbin/quotacheck -avugm'
/sbin/quotacheck -avugm

We recommend sites using file system quotas upgrade to this new package,
or edit /etc/rc.d/rc.M accordingly.";
tag_summary = "The remote host is missing an update as announced
via advisory SSA:2003-141-06a.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-141-06a";
                                                                                
if(description)
{
 script_id(53894);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_version("$");
 name = "Slackware Advisory SSA:2003-141-06a REVISED quotacheck security fix in rc.M ";
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

 script_summary("Slackware Advisory SSA:2003-141-06a REVISED quotacheck security fix in rc.M");

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
if(isslkpkgvuln(pkg:"sysvinit", ver:"2.84-i386-26", rls:"SLK9.0")) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
