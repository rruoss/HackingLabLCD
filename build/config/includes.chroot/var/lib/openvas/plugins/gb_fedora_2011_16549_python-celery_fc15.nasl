###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python-celery FEDORA-2011-16549
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
tag_insight = "An open source asynchronous task queue/job queue based on
  distributed message passing. It is focused on real-time
  operation, but supports scheduling as well.

  The execution units, called tasks, are executed concurrently
  on one or more worker nodes using multiprocessing, Eventlet
  or gevent. Tasks can execute asynchronously (in the background)
  or synchronously (wait until ready).

  Celery is used in production systems to process millions of
  tasks a day.

  Celery is written in Python, but the protocol can be implemented
  in any language. It can also operate with other languages using
  webhooks.

  The recommended message broker is RabbitMQ, but limited support
  for Redis, Beanstalk, MongoDB, CouchDB and databases
  (using SQLAlchemy or the Django ORM) is also available.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "python-celery on Fedora 15";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-December/070626.html");
  script_id(863660);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-12 12:02:25 +0530 (Mon, 12 Dec 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2011-16549");
  script_cve_id("CVE-2011-4356");
  script_name("Fedora Update for python-celery FEDORA-2011-16549");

  script_description(desc);
  script_summary("Check for the Version of python-celery");
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

if(release == "FC15")
{

  if ((res = isrpmvuln(pkg:"python-celery", rpm:"python-celery~2.2.8~1.fc15", rls:"FC15")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}