###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for mailman FEDORA-2011-2102
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Mailman is software to help manage email discussion lists, much like
  Majordomo and Smartmail. Unlike most similar products, Mailman gives
  each mailing list a webpage, and allows users to subscribe,
  unsubscribe, etc. over the Web. Even the list manager can administer
  his or her list entirely from the Web. Mailman also integrates most
  things people want to do with mailing lists, including archiving, mail
  &lt;-&gt; news gateways, and so on.

  Documentation can be found in: /usr/share/doc/mailman-2.1.13
  
  When the package has finished installing, you will need to perform some
  additional installation steps, these are described in:
  /usr/share/doc/mailman-2.1.13/INSTALL.REDHAT";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "mailman on Fedora 14";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-March/056387.html");
  script_id(862916);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-24 14:29:52 +0100 (Thu, 24 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2011-2102");
  script_cve_id("CVE-2011-0707", "CVE-2010-3089");
  script_name("Fedora Update for mailman FEDORA-2011-2102");

  script_description(desc);
  script_summary("Check for the Version of mailman");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.13~7.fc14", rls:"FC14")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
