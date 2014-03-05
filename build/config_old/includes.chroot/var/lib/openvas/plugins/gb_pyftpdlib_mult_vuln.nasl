###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pyftpdlib_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# pyftpdlib FTP Server Multiple Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to cause a denial of service.
  Impact Level: Application";
tag_affected = "ftpserver.py in pyftpdlib before 0.5.2";
tag_insight = "- Race condition in the FTPHandler class allows remote attackers to cause a
    denial of service by establishing and then immediately closing a TCP
    connection.
  - Improper permission check for the NLST command allows remote authenticated
    users to bypass intended access restrictions and list the root directory via
    an FTP session.
  - Memory leak in the on_dtp_close function allows remote authenticated users
    to cause a denial of service by sending a QUIT command during a data transfer.";
tag_solution = "Upgrade to pyftpdlib version 0.5.2 or later,
  For updates refer to http://code.google.com/p/pyftpdlib/downloads/list";
tag_summary = "This host is running pyftpdlib FTP server and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801613);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-3494", "CVE-2009-5012", "CVE-2009-5013", "CVE-2009-5011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("pyftpdlib FTP Server Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=100");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=104");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=105");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=114");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/issues/detail?id=119");
  script_xref(name : "URL" , value : "http://code.google.com/p/pyftpdlib/source/browse/trunk/HISTORY");

  script_description(desc);
  script_summary("Check for the version of pyftpdlib");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("FTP");
  script_dependencies("gb_pyftpdlib_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
ver = get_kb_item("pyftpdlib/Ver");

if(ver != NULL)
{
  ## Check for pyftpdlib version < 0.5.2
  if(version_is_less(version:ver, test_version:"0.5.2")) {
     security_warning(port);
  }
}
