# OpenVAS Vulnerability Test
# $Id: sles9p5021688.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Security update for PHP4
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_summary = "The remote host is missing updates to packages that affect
the security of your system.  One or more of the following packages
are affected:

    php4-exif
    php4
    php4-session
    php4-sysvshm
    mod_php4-core
    php4-imap
    php4-fastcgi
    apache-mod_php4
    php4-servlet
    mod_php4-servlet
    apache2-mod_php4
    php4-pear
    php4-devel
    php4-mysql

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5021688 within the SuSE Enterprise Server 9 patch
database at http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(65397);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
 script_cve_id("CVE-2004-1019", "CVE-2004-1065", "CVE-2005-0524", "CVE-2005-0525", "CVE-2005-1042", "CVE-2005-1043", "CVE-2005-1921", "CVE-2005-2498", "CVE-2005-2491");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("SLES9: Security update for PHP4");


 script_description(desc);

 script_summary("SLES9: Security update for PHP4");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("SuSE Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"php4-exif", rpm:"php4-exif~4.3.4~43.44", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
