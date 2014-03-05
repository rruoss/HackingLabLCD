# OpenVAS Vulnerability Test
# $Id: sles9p5015608.nasl 15 2013-10-27 12:49:54Z jan $
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

    php4-imap
    php4-readline
    php4-iconv
    php4-servlet
    apache2-mod_php4
    php4-gd
    php4-sysvshm
    php4-pear
    php4-xslt
    php4-zlib
    php4-mcal
    php4-yp
    php4-wddx
    mod_php4
    mod_php4-apache2
    php4-ftp
    php4-swf
    php4-mime_magic
    php4-filepro
    php4-bcmath
    php4-exif
    php4-curl
    php4-sysvsem
    php4-mhash
    php4-fastcgi
    php4-sockets
    php4-shmop
    php4-unixODBC
    php4-mbstring
    php4-mysql
    php4-calendar
    php4
    php4-domxml
    php4-devel
    mod_php4-servlet
    apache-mod_php4
    php4-gettext
    php4-session
    php4-ldap
    php4-ctype
    mod_php4-core
    php4-recode
    php4-pgsql
    php4-dba
    php4-qtdom
    php4-gmp
    php4-bz2
    php4-dbase
    php4-mcrypt
    php4-snmp

For more information, please visit the referenced security
advisories.

More details may also be found by searching for keyword
5015608 within the SuSE Enterprise Server 9 patch
database at http://download.novell.com/patch/finder/";

tag_solution = "Please install the updates provided by SuSE.";
                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(65144);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-10 16:11:46 +0200 (Sat, 10 Oct 2009)");
 script_cve_id("CVE-2007-2727", "CVE-2007-3472", "CVE-2007-3475", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3478", "CVE-2007-3799");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
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
if ((res = isrpmvuln(pkg:"php4-imap", rpm:"php4-imap~4.3.4~43.82", rls:"SLES9.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
