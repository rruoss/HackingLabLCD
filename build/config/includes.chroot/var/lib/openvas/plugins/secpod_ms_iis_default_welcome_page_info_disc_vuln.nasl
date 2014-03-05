###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_default_welcome_page_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft IIS Default Welcome Page Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_solution = "No solution or patch is available as of 23rd February, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.iis.net/

  Workaround:
  Disable IIS Server if not being used.";

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Services";
tag_insight = "The flaw is due to misconfiguration of IIS Server, which allows to
  access default pages when the server is not used.";
tag_summary = "The host is running Microsoft IIS Webserver and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(802806);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-23 16:21:11 +0530 (Thu, 23 Feb 2012)");
  script_name("Microsoft IIS Default Welcome Page Information Disclosure Vulnerability");
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
  script_summary("Check if IIS Misconfiguration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 SecPod");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://www.iis.net/");
  script_xref(name : "URL" , value : "http://osvdb.org/2117");
  exit(0);
}


include("http_func.inc");

## Variable Initialization
iisPort = 0;
iisVer = NULL;
request = "";
response = "";


##Get IIS Port
iisPort = get_http_port(default:80);
if(!iisPort){
  iisPort = 80;
}

if(!get_port_state(iisPort)){
  exit(0);
}

##Get IIS Banner
iisVer = get_kb_item("IIS/" + iisPort + "/Ver");
if(!iisVer){
  exit(0);
}

##Send Request for default page
request = http_get(item:"/", port:iisPort);
response = http_send_recv(port:iisPort, data:request);

if(response && ((("<title id=titletext>Under Construction</title>" ><response) &&
   ("The site you were trying to reach does not currently have a default page" >< response)) ||
   (("welcome to iis 4.0" >< response) && ("microsoft windows nt 4.0 option pack" >< response)) ||
   (("<title>iis7</title>" >< response) && ('<img src="welcome.png" alt="iis7"' >< response)))){
  security_warning(port:iisPort);
}
