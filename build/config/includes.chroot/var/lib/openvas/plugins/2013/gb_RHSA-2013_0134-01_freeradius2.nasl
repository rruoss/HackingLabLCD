###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for freeradius2 RHSA-2013:0134-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "FreeRADIUS is an open-source Remote Authentication Dial-In User Service
  (RADIUS) server which allows RADIUS clients to perform authentication
  against the RADIUS server. The RADIUS server may optionally perform
  accounting of its operations using the RADIUS protocol.

  It was found that the &quot;unix&quot; module ignored the password expiration
  setting in '/etc/shadow'. If FreeRADIUS was configured to use this module
  for user authentication, this flaw could allow users with an expired
  password to successfully authenticate, even though their access should have
  been denied. (CVE-2011-4966)

  This update also fixes the following bugs:

  * After log rotation, the freeradius logrotate script failed to reload the
  radiusd daemon and log messages were lost. This update has added a command
  to the freeradius logrotate script to reload the radiusd daemon and the
  radiusd daemon re-initializes and reopens its log files after log rotation
  as expected. (BZ#787111)

  * The radtest script with the 'eap-md5' option failed because it passed the
  IP family argument when invoking the radeapclient utility and the
  radeapclient utility did not recognize the IP family. The radeapclient
  utility now recognizes the IP family argument and radtest now works with
  eap-md5 as expected. (BZ#846476)

  * Previously, freeradius was compiled without the '--with-udpfromto'
  option. Consequently, with a multihomed server and explicitly specifying
  the IP address, freeradius sent the reply with the wrong IP source address.
  With this update, freeradius has been built with the '--with-udpfromto&quot'
  configuration option and the RADIUS reply is always sourced from the IP
  address the request was sent to. (BZ#846471)

  Description truncated, for more information please check the Reference URL";


tag_affected = "freeradius2 on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-January/msg00017.html");
  script_id(870887);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:45 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2011-4966");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2013:0134-01");
  script_name("RedHat Update for freeradius2 RHSA-2013:0134-01");

  script_description(desc);
  script_summary("Check for the Version of freeradius2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"freeradius2", rpm:"freeradius2~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-debuginfo", rpm:"freeradius2-debuginfo~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-krb5", rpm:"freeradius2-krb5~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-ldap", rpm:"freeradius2-ldap~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-mysql", rpm:"freeradius2-mysql~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-perl", rpm:"freeradius2-perl~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-postgresql", rpm:"freeradius2-postgresql~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-python", rpm:"freeradius2-python~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-unixODBC", rpm:"freeradius2-unixODBC~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freeradius2-utils", rpm:"freeradius2-utils~2.1.12~5.el5", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}