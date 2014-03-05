###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_derby_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Derby Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let remote attackers to crack passwords by
  generating hash collisions.
  Impact Level: Application";
tag_affected = "Apache Derby versions before 10.6.1.0";
tag_insight = "The flaw is due to a weaknesses in the password hash generation
  algorithm used in Derby to store passwords in the database, performs a
  transformation that reduces the size of the set of inputs to SHA-1,
  which produces a small search space that makes it easier for local and
  possibly remote attackers to crack passwords by generating hash collisions.";
tag_solution = "Upgrade to Apache Derby version 10.6.1.0 or later,
  For updates refer to http://db.apache.org/derby/derby_downloads.html";
tag_summary = "The host is running Apache Derby and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801284);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2009-4269");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Apache Derby Information Disclosure Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://marcellmajor.com/derbyhash.html");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/DERBY-4483");
  script_xref(name : "URL" , value : "http://db.apache.org/derby/releases/release-10.6.1.0.cgi#Fix+for+Security+Bug+CVE-2009-4269");

  script_description(desc);
  script_summary("Check for the version of Apache Derby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_apache_derby_detect.nasl");
  script_require_ports("Services/apache_derby",1527);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get Apache Derby Port
port = get_kb_item("Services/apache_derby");
if(!port) {
  port = 1527;
}

if(!get_port_state(port)) {
  exit(0);
}

## Check for Apache Derby versions before 10.06.0
if(ver = get_kb_item(string("apache_derby/",port,"/version")))
{
  if(version_is_less(version: ver, test_version: "10.06.0"))
  {
    security_warning(port:port);
    exit(0);
  }
}
