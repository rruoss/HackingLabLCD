# OpenVAS Vulnerability Test
# $Id: webplus_install_path.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Talentsoft Web+ reveals install path
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "The remote web server is affected by an information disclosure flaw. 

Description :

The remote host appears to be running Web+ Application Server. 

The version of Web+ installed on the remote host reveals the physical
path of the application when it receives a script file error.";

tag_solution = "Apply the vendor-supplied patch.";

 desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;
if(description)
{
  script_id(12074);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");

 name = "Talentsoft Web+ reveals install path";
 script_name(name);

 script_description(desc);

 summary = "Checks for Webplus install path disclosure";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.talentsoft.com/Issues/IssueDetail.wml?ID=WP197");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);

foreach dir (cgi_dirs()) {
  req = http_get(item:string(dir, "/webplus.exe?script=", SCRIPT_NAME), port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ("Web+ Error Message" >< buf)
  {
    if (report_verbosity > 0) {
      path = strstr(buf, " '");
      path = ereg_replace(pattern:" and.*$", replace:"",string:path);

      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        path
      );
    }
    else report = desc;

    security_warning(port:port, data:report);
  }
}
