###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for awstats FEDORA-2011-14025
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
tag_insight = "Advanced Web Statistics is a powerful and featureful tool that generates
  advanced web server graphic statistics. This server log analyzer works
  from command line or as a CGI and shows you all information your log contains,
  in graphical web pages. It can analyze a lot of web/wap/proxy servers like
  Apache, IIS, Weblogic, Webstar, Squid, ... but also mail or ftp servers.

  This program can measure visits, unique vistors, authenticated users, pages,
  domains/countries, OS busiest times, robot visits, type of files, search
  engines/keywords used, visits duration, HTTP errors and more...
  Statistics can be updated from a browser or your scheduler.
  The program also supports virtual servers, plugins and a lot of features.
  
  With the default configuration, the statistics are available:
  <A HREF= &qt http://localhost/awstats/awstats.pl &qt >http://localhost/awstats/awstats.pl</A>";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "awstats on Fedora 14";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-October/068184.html");
  script_id(863596);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-21 16:31:29 +0200 (Fri, 21 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2011-14025");
  script_name("Fedora Update for awstats FEDORA-2011-14025");

  script_description(desc);
  script_summary("Check for the Version of awstats");
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

  if ((res = isrpmvuln(pkg:"awstats", rpm:"awstats~7.0~4.fc14", rls:"FC14")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
