###############################################################################
# OpenVAS Vulnerability Test
# $Id:gb_phpmyadmin_csrf_mult.nasl 711 2008-12-23 17:30:29Z dec $
#
# phpMyAdmin Multiple CSRF SQL Injection Vulnerabilities
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can compromise database, modify the data or
  can compromise the whole web application.";
tag_affected = "phpMyAdmin, phpMyAdmin version 2.11 to 2.11.9.3 and 3.0 to 3.1.0.9.";
tag_insight = "This flaw is due to failure in sanitizing user-supplied data before being
  used in the SQL queries via a link or IMG tag to tbl_structure.php with a
  modified table parameter.";
tag_solution = "Upgrade to version 2.11.9.4 or 3.1.1.0
  http://www.phpmyadmin.net";
tag_summary = "This host is running phpMyAdmin and is prone to multiple
  CSRF Injection vulnerability.";

if(description)
{
  script_id(800210);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-23 15:23:02 +0100 (Tue, 23 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5621");
  script_bugtraq_id(32720);
  script_name("phpMyAdmin Multiple CSRF SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7382");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2008-10.php");
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-December/msg00784.html");

  script_description(desc);
  script_summary("Check for the version of phpMyAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  port = 80;
}

foreach path (make_list("/phpmyadmin/", cgi_dirs()))
{

  sndReq = http_get(item:string(path, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);

  if(rcvRes == NULL){
    exit(0);
  }

  if("phpMyAdmin" >< rcvRes)
  {
    phpVer = eregmatch(pattern:"phpMyAdmin ([0-9.]+)", string:rcvRes);
    if(phpVer[1] != NULL)
    {
      # Grep for version 2.11 to 2.11.9.3 and 3.0 to 3.1.0.9
      if(version_in_range(version:phpVer[1], test_version:"2.11",
                          test_version2:"2.11.9.3") ||
         version_in_range(version:phpVer[1], test_version:"3.0",
                          test_version2:"3.1.0.9")){
        security_hole(port);
      }
    }
    exit(0);
  }
}
