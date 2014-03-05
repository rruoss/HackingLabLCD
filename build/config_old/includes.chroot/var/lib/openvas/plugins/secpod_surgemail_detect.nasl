###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_surgemail_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# SurgeMail Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of SurgeMail
  and sets the result in KB.";

if(description)
{
  script_id(900839);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("SurgeMail Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of SurgeMail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl", "find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900839";
SCRIPT_DESC = "SurgeMail Version Detection";

function SurgeMailSetVer(banner)
{
  version = eregmatch(pattern:"Version ([0-9.]+)([a-z][0-9]?(-[0-9])?)?",
                      string:banner);
  if(version[1])
  {
    if(!isnull(version[2]))
      version = version[1] + "." + version[2];
    else
      version = version[1];

    version = ereg_replace(pattern:"-", replace:".", string:version);

    if(version) {
      set_kb_item(name:"SurgeMail/Ver", value:version);
      security_note(data:"SurgeMail version " + version +
                         " was detected on the host");

      ## build cpe and store it as host_detail
      cpe = build_cpe(value: version, exp:"^([0-9.]+([a-z0-9])?)",base:"cpe:/a:netwin:surgemail:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}


surge_banner = get_http_banner(port:7110);

if("surgemail" >< surge_banner){
  SurgeMailSetVer(banner:surge_banner);
  exit(0);
}

# Grep for Default Port
surgemail_port = get_http_port(default:7026);

if(!surgemail_port){
  surgemail_port = 7026;
}

# Check for Default Port Status
if(!get_port_state(surgemail_port))
{
  exit(0);
}

sndReq = http_get(item:"/", port:surgemail_port);
rcvRes = http_send_recv(port:surgemail_port, data:sndReq);

if(egrep(pattern:"SurgeMail", string:rcvRes, icase:1))
{
  smtpPort = get_kb_item("Services/smtp");
  if(!smtpPort)
    smtpPort = 25;

  imapPort = get_kb_item("Services/imap");
  if(!imapPort)
    imapPort = 143;

  popPort = get_kb_item("Services/pop3");
  if(!popPort)
    popPort = 110;

  foreach port (make_list(smtpPort, imapPort, popPort))
  {
    surge_banner = get_kb_item(string("Banner/", port));

    if(surge_banner =~ "surgemail"){
      SurgeMailSetVer(banner:surge_banner);
      exit(0);
    }
  }
}
