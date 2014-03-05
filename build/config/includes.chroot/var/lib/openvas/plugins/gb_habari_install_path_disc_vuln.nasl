###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_habari_install_path_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Habari Installation Path Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to gain sensitive information
  like installation path location.
  Impact Level: Application";
tag_affected = "Habari 0.7.1 and prior.";
tag_insight = "The flaw is caused by improper validation of certain user-supplied input
  passed, which allows attacker to gain sensitive information.";
tag_solution = "No solution or patch is available as of 8th August, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://habariproject.org/en/";
tag_summary = "This host is running Habari and is prone to path disclosure
  vulnerability.";

if(description)
{
  script_id(802320);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-10 13:49:51 +0200 (Wed, 10 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Habari Installation Path Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=265");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Habari_Info_Disc_Vuln.txt");

  script_description(desc);
  script_summary("Check if Habari is prone to path disclosure vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)) {
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir(make_list("/habari", "/myhabari", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get (item: string(dir, "/"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq);

  ## Confirm the application
  if("<title>My Habari</title>" >< rcvRes)
  {
    ## Construct the exploit request
    sndReq = http_get(item:string(dir, "/config.php"), port:port);
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Check the source code of the function in response
    if(egrep(pattern:"<b>Fatal error</b>:  Class 'Config' not found in.*\c" +
                     "onfig.php", string:rcvRes))
    {
      security_warning(port);
      exit(0);
    }
  }
}
