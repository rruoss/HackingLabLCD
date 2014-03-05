##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vaadin_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Vaadin URI Parameter Cross Site Scripting Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected
  application.
  Impact Level: Application.";
tag_affected = "Vaadin version prior to 6.4.9";

tag_insight = "Input passed to the 'URL' parameter in 'index.php', is not properly
  sanitised before being returned to the user.";
tag_solution = "Upgrade to Vaadin version 6.4.9 or later
  For updates refer to http://vaadin.com/releases";
tag_summary = "This host is running Vaadin is prone to Cross-Site Scripting
  vulnerability.";

if(description)
{
  script_id(902330);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-05 04:12:38 +0100 (Sat, 05 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(45779);
  script_cve_id("CVE-2011-0509");
  script_name("Vaadin URI Parameter Cross Site Scripting Vulnerability");
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


  script_description(desc);
  script_summary("Check for the version of Vaadin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/70398");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42879");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64626");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get the default port
vaadinPort = get_http_port(default:8888);
if(!vaadinPort){
  vaadinPort = 8888;
}

## check the port state
if(!get_port_state(vaadinPort)){
  exit(0);
}

## Send and recieve the data
sndReq = http_get(item: "/", port:vaadinPort);
rcvRes = http_keepalive_send_recv(port:vaadinPort, data:sndReq);

## Confirm the application
if("<title>Vaadin" >< rcvRes)
{
  vaadinVer = eregmatch(pattern:">[vV]ersion ([0-9.]+)" , string:rcvRes);
  if(vaadinVer[1] != NULL)
  {
    if(version_is_less(version:vaadinVer[1], test_version:"6.4.9")){
      security_warning(vaadinPort);
    }
  }
}
