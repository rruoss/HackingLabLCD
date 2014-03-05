###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_coldcalendar_eventid_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ColdGen ColdCalendar 'EventID' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "ColdGen ColdCalendar version 2.06";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'EventID' parameter in index.cfm, which allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 11th October 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.coldgen.com/index.cfm?ColdGen=ProductDetails&ProductID=3";
tag_summary = "This host is running ColdGen ColdCalendar and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(802253);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_bugtraq_id(43035);
  script_cve_id("CVE-2010-4910");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("ColdGen ColdCalendar 'EventID' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41333");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61637");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14932/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/93557/coldcalendar-sql.txt");

  script_description(desc);
  script_summary("Check if ColdCalendar is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/coldcal", "/coldcalendar", "", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get (item: dir + "/index.cfm", port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if("<title>ColdCalendar" >< res)
  {
    ## Construct Attack Request
    url = dir + "/index.cfm?fuseaction=ViewEventDetails&EventID=1+and+1";

    ## Try SQL injection and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"Error Executing Database " +
       "Query", extra_check: make_list('SELECT *', 'WHERE EventID = 1 and 1')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
