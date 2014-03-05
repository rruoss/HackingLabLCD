##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_b2epms_mult_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# b2ePMS Multiple SQL Injection Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to cause SQL injection attack and
  gain sensitive information.
  Impact Level: Application";
tag_affected = "b2ePMS version 1.0";
tag_insight = "Multiple flaws are due to input passed via phone_number, msg_caller,
  phone_msg, msg_options, msg_recipients and signed parameters to 'index.php'
  is not properly sanitised before being used in SQL queries, which allows
  attackers to execute arbitrary SQL commands in the context of an affected
  application or site.";
tag_solution = "No solution or patch is available as of 01st, June 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://developer.berlios.de/projects/b2epms/";
tag_summary = "This host is running b2ePMS and is prone to multiple SQL injection
  vulnerabilities.";

if(description)
{
  script_id(802861);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53690);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-01 13:07:29 +0530 (Fri, 01 Jun 2012)");
  script_name("b2ePMS Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53690");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/75923");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18935");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113064/b2epms10-sql.txt");

  script_description(desc);
  script_summary("Check if b2ePMS is vulnerable to SQL Injection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

## Variable Initialization
dir = "";
req = "";
res = "";
host = "";
postdata = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Host Name or IP
host = get_host_name();
if(!host){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/b2epms", cgi_dirs()))
{
  ## Confirm the application before trying exploit
  if(http_vuln_check(port:port, url: dir + "/index.php", check_header: TRUE,
     pattern:"<title>b2ePMS", extra_check: "New Phone Message"))
  {
    ## Construct attack request
    postdata = "phone_number='&phone_msg=SQL-TEST&msg_options=Please+call&" +
               "msg_recipients%5B%5D=abc%40gmail.com&signed=LOC&Submit=Send";

    req = string("POST ", dir, "/post_msg.php HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Referer: http://", host, dir, "/index.php\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n\r\n",
                  postdata);

    ## Send request and receive the response
    res = http_keepalive_send_recv(port:port, data:req);

    ## Confirm exploit worked by checking the response
    if(res && ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res) &&
      ('You have an error in your SQL syntax;' >< res))
    {
      security_hole(port);
      exit(0);
    }
  }
}
