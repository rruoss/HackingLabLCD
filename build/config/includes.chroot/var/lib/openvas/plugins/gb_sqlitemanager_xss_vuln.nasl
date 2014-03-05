##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sqlitemanager_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SQLiteManager Cross-Site Scripting Vulnerability
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to disclose sensitive information,
  or conduct cross-site scripting attacks.
  Impact Level: Application.";
tag_affected = "SQLiteManager version 1.2.0 and prior.";
tag_insight = "- Input passed to the 'redirect' parameter in 'main.php' is not properly
    sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 15th January 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sqlitemanager.org/index.php";
tag_summary = "This host is running SQLiteManager and is prone to Cross Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(800281);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4539");
  script_bugtraq_id(36002);
  script_name("SQLiteManager Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/28642");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36002");

  script_description(desc);
  script_summary("Check for the version of SQLiteManager");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
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

sqlPort = get_http_port(default:80);
if(!sqlPort){
  exit(0);
}

sqliteVer = get_kb_item("www/" + sqlPort + "/SQLiteManager");
if(!sqliteVer){
  exit(0);
}

sqliteVer = eregmatch(pattern:"^(.+) under (/.*)$", string:sqliteVer);
if(!safe_checks())
{
  sndReq = http_get(item:string(sqliteVer[2], "/main.php?redirect=<script>" +
                    "alert('Exploit-XSS')</script>"), port:sqlPort);
  rcvRes = http_send_recv(port:sqlPort, data:sndReq);
  if("Exploit-XSS" >< rcvRes);
  {
    security_warning(sqlPort);
    exit(0);
  }
}

if(sqliteVer[1] != NULL)
{
  if(version_is_less_equal(version:sqliteVer[1], test_version:"1.2.0")){
    security_warning(sqlPort);
  }
}
