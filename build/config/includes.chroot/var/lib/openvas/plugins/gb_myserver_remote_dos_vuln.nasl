###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_myserver_remote_dos_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# MyServer Remote Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful attacks will lead to denial of service to legitimate users.
  Impact Level: Application";
tag_affected = "MyServer MyServer version 0.8.11 and prior on all running platforms.";
tag_insight = "The flaw is due to multiple invalid requests in HTTP GET, DELETE,
  OPTIONS, and possibly other methods. These requests are related to
  '204 No Content error'.";
tag_solution = "Upgrade to MyServer version 0.9 or later.
  For updates refer to ftp://ftp.gnu.org/gnu/myserver/0.9/";
tag_summary = "This host is running MyServer and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(800306);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5160");
  script_bugtraq_id(27981);
  script_name("MyServer Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5184");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/27981");
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2008-5160");

  script_description(desc);
  script_summary("Check for the Version of MyServer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
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

port = get_http_port(default:80);
if(!port){
  exit(0);
}

banner = get_http_banner(port);
if(!banner){
  exit(0);
}

mysvrVer = eregmatch(pattern:"MyServer ([0-9.]+)", string:banner);
if(mysvrVer[1] != NULL)
{
  # MyServer Version 0.8.11 and prior
  if(version_is_less_equal(version:mysvrVer[1], test_version:"0.8.11")){
    security_warning(port);
  }
}
