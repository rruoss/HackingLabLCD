##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_timelive_time_n_expense_tracking_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# TimeLive Time And Expense Tracking Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the running version of TimeLive Time and
  Expense Tracking and sets the result in KB";

if(description)
{
  script_id(902480);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-30 15:58:03 +0200 (Fri, 30 Sep 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("TimeLive Time And Expense Tracking Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of TimeLive Time And Expense Tracking");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");


## Get the default port
tlPort = get_http_port(default:80);
if(!tlPort){
  tlPort = 80;
}

##Check the port status
if(!get_port_state(tlPort)){
  exit(0);
}

## make the list of possible paths
foreach dir (make_list("/TimeLive/", "/TimeTracking/", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "default.aspx"), port:tlPort);
  rcvRes = http_send_recv(port:tlPort, data:sndReq);

  ## Cinfirm the application
  if("TimeLive - Online web timesheet and time tracking solution" >< rcvRes &&
     "Livetecs LLC" >< rcvRes)
  {
    ## Match the version
    tlVer = eregmatch(pattern:">v ([0-9.]+)", string:rcvRes);
    if(tlVer[1] != NULL)
    {
      tmp_version = tlVer[1] + " under " + dir;

      ## Set the version in KB
      set_kb_item(name:"www/"+ tlPort + "/TimeLive", value:tmp_version);
      security_note(data:"TimeLive Time version " + tlVer[1] + " running at " +
                         "location " + dir +  " was detected on the host");
    }
  }
}
