##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eclipse_ide_help_contents_mult_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Eclipse IDE Help Contents Multiple Cross-site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_affected = "Eclipse IDE Version 3.3.2";

tag_insight = "- Input passed to the 'searchWord' parameter in 'help/advanced/searchView.jsp' and
    'workingSet' parameter in 'help/advanced/workingSetManager.jsp' are not
    properly sanitised before being returned to the user.";
tag_solution = "Upgrade to Eclipse IDE Version 3.6.2 or later
  For updates refer to http://www.eclipse.org/downloads/";
tag_summary = "This host is running Eclipse IDE is prone to multiple Cross-Site
  Scripting vulnerabilities.";

if(description)
{
  script_id(801746);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-7271");
  script_name("Eclipse IDE Help Contents Multiple Cross-site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://r00tin.blogspot.com/2008/04/eclipse-local-web-server-exploitation.html");

  script_description(desc);
  script_summary("Check if Eclipse IDE is vulnerable to XSS attacks");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Listens on the ports in the range 900-70000
ports = get_kb_list("Ports/tcp/*");

if(max_index(ports) < 1)exit(0);

foreach port (keys(ports))
{
  ecPort = eregmatch(string:port, pattern: "Ports/tcp/([0-9]+)");
  if(get_port_state(ecPort[1]))
  {
    ## send and receive the response
    sndReq = http_get(item: "/help/index.jsp", port:ecPort[1]);
    rcvRes = http_keepalive_send_recv(port:ecPort[1], data:sndReq);

    ## Confirm the application
    if("<title>Help - Eclipse" >< rcvRes)
    {
      sndReq = http_get(item: '/help/advanced/searchView.jsp?searchWord=a");}alert' +
                                '("OpenVAS-XSS-Testing");</script>', port:ecPort[1]);
      rcvRes = http_keepalive_send_recv(port:ecPort[1], data:sndReq);

      ## Check the response to confirm vulnerability
      if('alert("OpenVAS-XSS-Testing");</script>' >< rcvRes)
      {
        security_warning(ecPort[1]);
        exit(0);
      }
    }
  }
}
