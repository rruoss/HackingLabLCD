###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for httpd RHSA-2008:0008-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The Apache HTTP Server is a popular Web server.

  A flaw was found in the mod_imagemap module. On sites where mod_imagemap
  was enabled and an imagemap file was publicly available, a cross-site
  scripting attack was possible. (CVE-2007-5000)
  
  A flaw was found in the mod_autoindex module. On sites where directory
  listings are used, and the &quot;AddDefaultCharset&quot; directive has been removed
  from the configuration, a cross-site scripting attack might have been
  possible against Web browsers which do not correctly derive the response
  character set following the rules in RFC 2616. (CVE-2007-4465)
  
  A flaw was found in the mod_status module. On sites where mod_status was
  enabled and the status pages were publicly available, a cross-site
  scripting attack was possible. (CVE-2007-6388)
  
  A flaw was found in the mod_proxy_balancer module. On sites where
  mod_proxy_balancer was enabled, a cross-site scripting attack against an
  authorized user was possible. (CVE-2007-6421)
  
  A flaw was found in the mod_proxy_balancer module. On sites where
  mod_proxy_balancer was enabled, an authorized user could send a carefully
  crafted request that would cause the Apache child process handling that
  request to crash. This could lead to a denial of service if using a
  threaded Multi-Processing Module. (CVE-2007-6422) 
  
  A flaw was found in the mod_proxy_ftp module. On sites where mod_proxy_ftp
  was enabled and a forward proxy was configured, a cross-site scripting
  attack was possible against Web browsers which do not correctly derive the
  response character set following the rules in RFC 2616. (CVE-2008-0005)
  
  Users of Apache httpd should upgrade to these updated packages, which
  contain backported patches to resolve these issues. Users should restart
  httpd after installing this update.";

tag_affected = "httpd on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-January/msg00009.html");
  script_id(870034);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2008:0008-01");
  script_cve_id("CVE-2007-4465", "CVE-2007-5000", "CVE-2007-6388", "CVE-2007-6421", "CVE-2007-6422", "CVE-2008-0005");
  script_name( "RedHat Update for httpd RHSA-2008:0008-01");

  script_description(desc);
  script_summary("Check for the Version of httpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~11.el5_1.3", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.3~11.el5_1.3", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~11.el5_1.3", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~11.el5_1.3", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~11.el5_1.3", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
