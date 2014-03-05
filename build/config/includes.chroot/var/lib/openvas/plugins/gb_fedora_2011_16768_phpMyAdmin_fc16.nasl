###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for phpMyAdmin FEDORA-2011-16768
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "phpMyAdmin is a tool written in PHP intended to handle the administration of
  MySQL over the World Wide Web. Most frequently used operations are supported
  by the user interface (managing databases, tables, fields, relations, indexes,
  users, permissions), while you still have the ability to directly execute any
  SQL statement.

  Features include an intuitive web interface, support for most MySQL features
  (browse and drop databases, tables, views, fields and indexes, create, copy,
  drop, rename and alter databases, tables, fields and indexes, maintenance
  server, databases and tables, with proposals on server configuration, execute,
  edit and bookmark any SQL-statement, even batch-queries, manage MySQL users
  and privileges, manage stored procedures and triggers), import data from CSV
  and SQL, export data to various formats: CSV, SQL, XML, PDF, OpenDocument Text
  and Spreadsheet, Word, Excel, LATEX and others, administering multiple servers,
  creating PDF graphics of your database layout, creating complex queries using
  Query-by-example (QBE), searching globally in a database or a subset of it,
  transforming stored data into any format using a set of predefined functions,
  like displaying BLOB-data as image or download-link and much more...";

tag_affected = "phpMyAdmin on Fedora 16";
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
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-December/071040.html");
  script_id(863999);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-02 12:53:08 +0530 (Mon, 02 Apr 2012)");
  script_cve_id("CVE-2011-4634");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2011-16768");
  script_name("Fedora Update for phpMyAdmin FEDORA-2011-16768");

  script_description(desc);
  script_summary("Check for the Version of phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~3.4.8~1.fc16", rls:"FC16")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}