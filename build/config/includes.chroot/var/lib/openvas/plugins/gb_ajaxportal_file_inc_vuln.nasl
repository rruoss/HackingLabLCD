###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ajaxportal_file_inc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# AjaxPortal 'di.php' File Inclusion Vulnerability
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
tag_impact = "Successful exploitation will let the remote attacker to execute arbitrary
  PHP code via a URL in the pathtoserverdata parameter.
  Impact Level: Application";
tag_affected = "MyioSoft, AjaxPortal version 3.0";
tag_insight = "The flaw is due to error in the 'pathtoserverdata' parameter in
  install/di.php and it can exploited to cause PHP remote file inclusion.";
tag_solution = "No solution or patch is available as of 02nd July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://myiosoft.com";
tag_summary = "The host is running AjaxPortal and is prone to File Inclusion
  vulnerability.";

if(description)
{
  script_id(800817);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2262");
  script_name("AjaxPortal 'di.php' File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504618/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of AjaxPortal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ajaxportal_detect.nasl");
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

ajaxPort = get_http_port(default:80);
if(!ajaxPort){
  exit(0);
}

foreach dir (make_list ("/", "/ajaxportal", "/portal", cgi_dirs()))
{
  sndReq = http_get(item:dir + "/install/index.php", port:ajaxPort);
  rcvRes = http_send_recv(data:sndReq, port:ajaxPort);
  if(rcvRes =~ "MyioSoft EasyInstaller" &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    ajaxVer = get_kb_item("www/" + ajaxPort + "/AjaxPortal");
    ajaxVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ajaxVer);
    if(ajaxVer[1] != NULL)
    {
      if(version_is_equal(version:ajaxVer[1], test_version:"3.0"))
      {
         security_hole(ajaxPort);
         exit(0);
      }
    }
  }
}
