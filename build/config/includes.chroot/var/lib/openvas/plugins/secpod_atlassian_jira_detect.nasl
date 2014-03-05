###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_atlassian_jira_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Atlassian JIRA Version Detection
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
tag_summary = "This script finds the installed Atlassian JIRA version and saves
  the result in KB";

if(description)
{
  script_id(902046);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_name("Atlassian JIRA Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_summary("Set the version of Atlassian JIRA in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

jiraPort = get_http_port(default:8080);
if(!jiraPort){
  exit(0);
}

sndReq = http_get(item:"/secure/Dashboard.jspa", port:jiraPort);
rcvRes = http_keepalive_send_recv(port:jiraPort, data:sndReq);

## Confirm Atlassian JIRA Application
if("Atlassian JIRA" >< rcvRes)
{
  jiraVer = eregmatch(pattern:" Version: ([0-9.]+)", string:rcvRes);
  if(jiraVer[1] != null) {
    jVer = jiraVer[1];
  } else {
    jiraVer = eregmatch(pattern:"\(v([0-9.]+#?[0-9]+?)\)", string:rcvRes);
    if(jiraVer[1] != null) {
      jVer = jiraVer[1];
    }  
  }  

  ## Set Atlassian JIRA Version in KB
  if(jVer != NULL){
   set_kb_item(name:"www/" + jiraPort + "/Atlassian_JIRA", value:jVer);
   security_note(data:"Atlassian JIRA version " + jVer +
                                          " was detected on the host");
  }
}
