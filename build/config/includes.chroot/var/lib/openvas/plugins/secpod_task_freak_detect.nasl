###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_task_freak_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Task Freak Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the installed Task Freak version and saves
  the result in KB.";

if(description)
{
  script_id(902053);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Task Freak Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of Task Freak in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902053";
SCRIPT_DESC = "Task Freak Version Detection";

tfPort = get_http_port(default:80);
if(!tfPort){
  tfPort = 80;
}

if(!get_port_state(tfPort)){
  exit(0);
}

foreach dir (make_list("/taskfreak", "/Taskfreak", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/login.php"), port:tfPort);
  rcvRes = http_send_recv(port:tfPort, data:sndReq);
  
  if(">TaskFreak! multi user<" >< rcvRes)
  {
    tfVer = eregmatch(pattern:"> v([0-9.]+)", string:rcvRes);
    if(tfVer[1] != NULL)
    {
      tmp_version = tfVer[1] + " under " + dir;
      set_kb_item(name:"www/" + tfPort + "/TaskFreak", value:tmp_version);
      security_note(data:"Task Freak version " + tfVer[1] + " running at location "
                         + dir + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:taskfreak:taskfreak%21:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}
