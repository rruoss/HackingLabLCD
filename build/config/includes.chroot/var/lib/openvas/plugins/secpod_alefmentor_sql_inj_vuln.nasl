###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_alefmentor_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# AlefMentor Multiple SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to conduct SQL injection
  attacks.
  Impact Level: Application.";
tag_affected = "AlefMentor version 2.0 to 2.2 on all running platform.";
tag_insight = "Input passed via the 'cont_id' and 'courc_id' parameters to 'cource.php' is
  not properly sanitised before being used in a SQL query. This flaw can be
  exploited to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 17th December, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.truesolution.net/downloads";
tag_summary = "The host is running AlefMentor and is prone to SQL Injection
  Vulnerability.";

if(description)
{
  script_id(901071);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4256");
  script_name("AlefMentor Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37626");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54624");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10358");

  script_description(desc);
  script_summary("Check the version AlefMentor and SQL Injection");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("secpod_alefmentor_detect.nasl");
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

amPort = get_http_port(default:80);
if(!amPort){
  exit(0);
}

amVer = get_kb_item("www/" + amPort + "/AlefMentor");
if(!amVer){
  exit(0);
}

amVer = eregmatch(pattern:"^(.+) under (/.*)$", string:amVer);
if(!safe_checks() && amVer[2] != NULL)
{
  request = http_get(item:amVer[2] + "/cource.php?action=pregled&cont_id" +
                                     "=[SQL]", port:amPort);
  response = http_send_recv(port:amPort, data:request);
  if("Da li si siguran da je to ta baza" >< response)
  {
    security_hole(amPort);
    exit(0);
  }
}

if(amVer[1] != NULL)
{
  if(version_in_range(version:amVer[1], test_version:"2.0",
                                       test_version2:"2.2")){
   security_hole(amPort);
  }
}