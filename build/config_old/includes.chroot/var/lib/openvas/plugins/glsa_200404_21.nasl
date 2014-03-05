# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "There is a bug in smbfs which may allow local users to gain root via a
setuid file on a mounted Samba share. Also, there is a tmpfile symlink
vulnerability in the smbprint script distributed with Samba.";
tag_solution = "All users should update to the latest version of the Samba package.

The following commands will perform the upgrade:

    # emerge sync

    # emerge -pv '>=net-fs/samba-3.0.2a-r2'
    # emerge '>=net-fs/samba-3.0.2a-r2'

Those who are using Samba's password database also need to run the
following command:

    # pdbedit --force-initialized-passwords

Those using LDAP for Samba passwords also need to check the
sambaPwdLastSet attribute on each account, and ensure it is not 0.

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200404-21
http://bugs.gentoo.org/show_bug.cgi?id=41800
http://bugs.gentoo.org/show_bug.cgi?id=45965
http://www.securityfocus.com/archive/1/353222/2004-04-09/2004-04-15/1
http://seclists.org/lists/bugtraq/2004/Mar/0189.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200404-21.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54560);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_name("Gentoo Security Advisory GLSA 200404-21 (samba)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200404-21 (samba)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/gentoo");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"net-fs/samba", unaffected: make_list("ge 3.0.2a-r2"), vulnerable: make_list("le 3.0.2a"))) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
