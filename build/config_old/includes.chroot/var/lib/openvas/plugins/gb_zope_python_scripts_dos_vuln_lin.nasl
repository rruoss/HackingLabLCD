###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zope_python_scripts_dos_vuln_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# Zope Python Scripts Local Denial of Service Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_solution = "Update Zope to higher version,
  http://www.zope.org/Products/Zope/
    or
  Apply available patch,
  http://www.zope.org/Products/Zope/Hotfix-2008-08-12/

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation allows remote authenticated users to cause
  denial of service or resource exhaustion.
  Impact Level: Application";
tag_affected = "Zope Versions 2.x - 2.11.2 on Linux.";
tag_insight = "Zope server allows improper strings to be passed via certain raise and
  import commands.";
tag_summary = "This host is running Zope, and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_id(800064);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5102");
  script_bugtraq_id(32267);
  script_name("Zope Python Scripts Local Denial of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.zope.org/advisories/advisory-2008-08-12");
  script_xref(name : "URL" , value : "http://www.zope.org/Products/Zope/Hotfix-2008-08-12/README.txt");

  script_description(desc);
  script_summary("Check for the Version of Zope");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

banner = get_http_banner(port);
if(!banner){
  exit(0);
}

zopeVer = eregmatch(pattern:"Zope ([0-9.]+)", string:banner);
if(zopeVer != NULL)
{
  if(version_in_range(version:zopeVer[1], test_version:"2.0", test_version2:"2.11.2")){
    security_warning(port);
  }
}
