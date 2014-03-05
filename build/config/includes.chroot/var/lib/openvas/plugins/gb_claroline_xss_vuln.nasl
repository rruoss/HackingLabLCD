###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_claroline_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Claroline 'notfound.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to compromise the application,
  access or modify data, or exploit latent vulnerabilities in the underlying
  database.
  Impact Level: Application";
tag_affected = "Claroline Version 1.8.11 and prior";
tag_insight = "The flaw is due to,
  - error in 'claroline/linker/notfound.php' which is not properly sanitising
    input data passed via the 'Referer' header, before being returned to the
    user.
  - error in 'group/group.php' which is not properly sanitising input data
    passed to the 'sort' parameter, before being used in an SQL query.";
tag_solution = "upgrade to the version version 1.8.12 or later
  For updates refer tohttp://www.claroline.net/download/stable.html";
tag_summary = "The host is running Claroline and is prone to SQL Injection
  Vulnerability.";

if(description)
{
  script_id(800628);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1907");
  script_bugtraq_id(34883);
  script_name("Claroline 'notfound.php' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35019");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50404");
  script_xref(name : "URL" , value : "http://gsasec.blogspot.com/2009/05/claroline-v1811-cross-site-scripting.html");

  script_description(desc);
  script_summary("Check for the Version of Claroline");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_claroline_detect.nasl");
  script_family("Web application abuses");
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

clarolinPort = get_http_port(default:80);
if(!clarolinPort){
  exit(0);
}

clarolineVer = get_kb_item("www/"+ clarolinPort + "/Claroline");
if(!clarolineVer){
  exit(0);
}

clarolineVer = eregmatch(pattern:"^(.+) under (/.*)$", string:clarolineVer);
if(clarolineVer[1] != NULL)
{
  if(version_is_less_equal(version:clarolineVer[1], test_version:"1.8.11")){
    security_warning(clarolinPort);
  }
}
