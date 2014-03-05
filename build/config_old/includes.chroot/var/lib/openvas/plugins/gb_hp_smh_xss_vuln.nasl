##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP System Management Homepage Cross site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  script on the user's web browser by injecting web script and steal cookie
  based authentication credentials.
  Impact Level: Application.";
tag_affected = "HP System Management Homepage (SMH) versions prior to 6.0 on all platforms.";

tag_insight = "The flaw is caused by an input validation error in the 'proxy/smhui/getuiinfo'
  script when processing the 'servercert' parameter.";
tag_solution = "Upgarde to HP SMH version 6.0.0.96(for windows), 6.0.0-95(for linux),
  http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02000727";
tag_summary = "This host is running  HP System Management Homepage (SMH) and is
  prone to Cross site scripting vulnerability.";

if(description)
{
  script_id(800293);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(38081);
  script_cve_id("CVE-2009-4185");
  script_name("HP System Management Homepage Cross-site scripting Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=126529736830358&amp;w=2");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0294");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509195/100/0/threaded");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

smhPort = get_http_port(default:2301);
if(!get_port_state(smhPort)){
  exit(0);
}

smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer != NULL)
{
  if(version_is_less(version:smhVer, test_version:"6.0")){
    security_warning(smhPort);
  }
}
