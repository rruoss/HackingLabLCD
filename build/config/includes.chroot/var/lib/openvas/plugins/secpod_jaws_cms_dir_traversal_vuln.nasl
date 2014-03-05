##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jaws_cms_dir_traversal_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Jaws CMS Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute local file inclusion
  attacks and gain sensitive information about the remote system directories
  where Jaws CMS runs.

  Impact level: Application/System";

tag_affected = "Jaws CMS 0.8.8 and prior";
tag_insight = "This flaw is due to error in file 'index.php' in 'language'
  parameter which lets the attacker execute local file inclusion attacks.";
tag_solution = "Upgrade to the latest version 0.8.9
  http://www.jaws-project.com";
tag_summary = "This host is running Jaws CMS and is prone to Directory
  Traversal Vulnerability.";

if(description)
{
  script_id(900460);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(33607);
  script_cve_id("CVE-2009-0645");
  script_name("Jaws CMS Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7976");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48476");

  script_description(desc);
  script_summary("Check for version of Jaws CMS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

jawsPort = get_kb_item("Services/www");
if(!get_port_state(jawsPort)){
  exit(0);
}

foreach path(make_list("/", cgi_dirs()))
{
  request = http_get(item:"/jaws/index.php", port:jawsPort);
  response = http_keepalive_send_recv(port:jawsPort, data:request);
  if(response == NULL){
    exit(0);
  }
  if("Jaws" >< response)
  {
    version = eregmatch(pattern:"Jaws ([0-9.]+)", string:response);
    if(version[1] != NULL)
    {
      if(version_is_less_equal(version:version[1], test_version:"0.8.8"))
      {
        security_hole(jawsPort);
        exit(0);
      }
    }
    exit(0);
  }
}
exit(0);
