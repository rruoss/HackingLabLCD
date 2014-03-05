###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rhinosoft_serv-u_site_set_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Rhino Software Serv-U 'SITE SET' Command Denial Of Service vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the local attackers to cause a Denial of
  Service in the affected application.
  Impact Level: Application";
tag_affected = "Rhino Software Serv-U version prior to 9.0.0.1";
tag_insight = "An error occurs when application handles the 'SITE SET TRANSFERPROGRESS ON'
  command.";
tag_solution = "Upgrade to Rhino Software Serv-U version 9.0.0.1 or later.
  For updates refer to http://www.serv-u.com/dn.asp";
tag_summary = "This host is installed with Rhino Software Serv-U and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(801118);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3655");
  script_name("Rhino Software Serv-U 'SITE SET' Command Denial Of Service vulnerability");
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
  script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36873/");

  script_description(desc);
  script_summary("Check  the version of Rhino Software Serv-U");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_rhinosoft_serv-u_detect.nasl", "find_service.nasl",
                      "ssh_detect.nasl");
  script_require_keys("Serv-U/FTP/Ver");
  script_require_ports("Services/ftp", 21, "Services/ssh", 22);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

servuPort = get_kb_item("Services/ssh");
if(!servuPort)
{
  servuPort = get_kb_item("Services/ftp");
  if(!servuPort)
    exit(0);
}

servuVer = get_kb_item("Serv-U/FTP/Ver");
# Check for Rhino Software Serv-U versions < 9.0.0.1
if(servuVer =~ "^(7|8)\..*"){
  security_warning(servuPort);
}
