##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pi3web_isapi_request_dos_vuln_900402.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Pi3Web ISAPI Requests Handling DoS Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_affected = "Pi3Wed.org Pi3Web version 2.0.13 and prior on all running platforms.

  Workaround:
  - Disable ISAPI mapping in server configuration in Server Admin-> Mapping Tab.
  - Delete the users.txt, install.daf and readme.daf in ISAPI folder.";

tag_impact = "Successful exploitation will crash Pi3Web Server.
  Impact Level: Application/Network";
tag_insight = "This vulnerability is due to insufficient checks on incoming HTTP 
  requests in the 'ISAPI' directory. This can be exploited via 'install.daf',
  'readme.daf', or 'users.txt' files in the affected directory.";
tag_summary = "Pi3Web is prone to ISAPI Requests Handling DoS vulnerability.";

if(description)
{
  script_id(900402);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-6938");
 script_bugtraq_id(32287);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Pi3Web ISAPI Requests Handling DoS Vulnerability");
  script_summary("Check for vulnerable version of Pi3Web");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected;

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7109/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32696/");
  script_xref(name : "URL" , value : "http://pi3web.sourceforge.net/pi3web/files/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/32287/info/");

  script_description(desc);
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);
if(!port){
  port = 8080;
}

if(get_port_state(port))
{
  request = http_get(item:"/", port:port);
  response = http_send_recv(port:port, data:request);
  if(response == NULL){
    exit(0); 
  }
  if("Pi3Web" >< response)
  {
    if(safe_checks())
    {
      pattern = "Pi3Web/(^[01](\..*)|2\.0(\.[0-3])?)";
      if(egrep(pattern:pattern, string:response)){
        security_warning(port);
        exit(0);
      }
    }
    req = http_get(item:"/isapi/users.txt", port:port);
    resp = http_send_recv(port:port, data:req);
    if("500 Internal Error" >< resp){
      security_warning(port);
    }
  }
}
