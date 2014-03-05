# OpenVAS Vulnerability Test
# $Id: RHSA_2009_1563.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory RHSA-2009:1563 ()
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
tag_summary = "The remote host is missing updates announced in
advisory RHSA-2009:1563.

Apache Tomcat is a servlet container for the Java Servlet and JavaServer
Pages (JSP) technologies.

It was discovered that the Red Hat Security Advisory RHSA-2008:0195 did not
address all possible flaws in the way Tomcat handles certain characters and
character sequences in cookie values. A remote attacker could use this flaw
to obtain sensitive information, such as session IDs, and then use this
information for session hijacking attacks. (CVE-2007-5333)

Note: The fix for the CVE-2007-5333 flaw changes the default cookie
processing behavior: With this update, version 0 cookies that contain
values that must be quoted to be valid are automatically changed to version
1 cookies. To reactivate the previous, but insecure behavior, add the
following entry to the /etc/tomcat5/catalina.properties file:

org.apache.tomcat.util.http.ServerCookie.VERSION_SWITCH=false

It was discovered that request dispatchers did not properly normalize user
requests that have trailing query strings, allowing remote attackers to
send specially-crafted requests that would cause an information leak.
(CVE-2008-5515)

A flaw was found in the way the Tomcat AJP (Apache JServ Protocol)
connector processes AJP connections. An attacker could use this flaw to
send specially-crafted requests that would cause a temporary denial of
service. (CVE-2009-0033)

It was discovered that the error checking methods of certain authentication
classes did not have sufficient error checking, allowing remote attackers
to enumerate (via brute force methods) usernames registered with
applications running on Tomcat when FORM-based authentication was used.
(CVE-2009-0580)

It was discovered that web applications containing their own XML parsers
could replace the XML parser Tomcat uses to parse configuration files. A
malicious web application running on a Tomcat instance could read or,
potentially, modify the configuration and XML-based data of other web
applications deployed on the same Tomcat instance. (CVE-2009-0783)

Users of Tomcat should upgrade to these updated packages, which contain
backported patches to resolve these issues. Tomcat must be restarted for
this update to take effect.";

tag_solution = "Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if(description)
{
 script_id(66183);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-11 15:56:44 +0100 (Wed, 11 Nov 2009)");
 script_cve_id("CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0783");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("RedHat Security Advisory RHSA-2009:1563");


 script_description(desc);

 script_summary("Redhat Security Advisory RHSA-2009:1563");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Red Hat Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1563.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
 script_xref(name : "URL" , value : "http://www.redhat.com/security/updates/classification/#important");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"tomcat5", rpm:"tomcat5~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-common-lib", rpm:"tomcat5-common-lib~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jasper", rpm:"tomcat5-jasper~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-jsp-2.0-api", rpm:"tomcat5-jsp-2.0-api~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-server-lib", rpm:"tomcat5-server-lib~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"tomcat5-servlet-2.4-api", rpm:"tomcat5-servlet-2.4-api~5.5.23~0jpp_18rh", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
