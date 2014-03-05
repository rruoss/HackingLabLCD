###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sqlitemanager_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Sqlitemanager Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the installed  Sqlitemanager version and saves
  the result in KB.";

if(description)
{
  script_id(800280);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sqlitemanager Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Sqlitemanager in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");

sqlPort = get_http_port(default:80);
if(!sqlPort){
  exit(0);
}

foreach dir (make_list("/SQLiteManager" , cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/main.php"), port:sqlPort);
  rcvRes = http_send_recv(port:sqlPort, data:sndReq);

  if("SQLiteManager" >< rcvRes)
  {
    sqlVer = eregmatch(pattern:"> version ([0-9.]+)" , string:rcvRes);
    if(sqlVer[1] != NULL)
    {
      set_kb_item(name:"www/" + sqlPort + "/SQLiteManager",
                  value:sqlVer[1] + " under " + dir);
      security_note(data:"Sqlitemanager version " + sqlVer[1] + 
                    " running at location " + dir + " was detected on the host");
      exit(0);
    }
  }
}
