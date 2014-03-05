###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_twiki_xss_n_cmd_exec_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# TWiki XSS and Command Execution Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow execution of arbitrary script code or
  commands. This could let attackers steal cookie-based authentication
  credentials or compromise the affected application.
  Impact Level: Application";
tag_affected = "TWiki, TWiki version prior to 4.2.4.";
tag_insight = "The flaws are due to,
  - %URLPARAM{}% variable is not properly sanitized which lets attackers
    conduct cross-site scripting attack.
  - %SEARCH{}% variable is not properly sanitised before being used in an
    eval() call which lets the attackers execute perl code through eval
    injection attack.";
tag_solution = "Upgrade to version 4.2.4 or later,
  http://twiki.org/cgi-bin/view/Codev/TWikiRelease04x02x04";
tag_summary = "The host is running TWiki and is prone to Cross-Site Scripting
  (XSS) and Command Execution Vulnerabilities.";

if(description)
{
  script_id(800320);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-16 16:12:00 +0100 (Tue, 16 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-5304", "CVE-2008-5305");
  script_bugtraq_id(32668, 32669);
  script_name("TWiki XSS and Command Execution Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://twiki.org/cgi-bin/view/Codev.SecurityAlert-CVE-2008-5304");
  script_xref(name : "URL" , value : "http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2008-5305");

  script_description(desc);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_summary("Check for the Version of TWiki");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/twiki", cgi_dirs()))
{
  soc = http_open_socket(port);
  if(!soc){
    exit(0);
  }

  sndReq = http_get(item:path + "/bin/view/TWiki/WebHome", port:port);
  send(socket:soc, data:sndReq);
  rcvRes = http_recv(socket:soc);
  http_close_socket(soc);

  if(!rcvRes){
    exit(0);
  }

  if(rcvRes =~ "Powered by TWiki")
  {
    twikiVer = eregmatch(pattern:"TWiki-([0-9.]+),", string:rcvRes);
    if(twikiVer[1] != NULL)
    {
      if(version_is_less(version:twikiVer[1], test_version:"4.2.4")){
        security_hole(port);
      }
    }
    exit(0);
  }
}
