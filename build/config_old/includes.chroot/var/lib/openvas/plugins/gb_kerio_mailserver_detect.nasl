###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_mailserver_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Kerio Mail Server Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated to Detect the Patch Version
#    - By Antu Sanadi <santu@secpod.com> On 2009-08-07
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script will detect the version of Kerio Mail Server Web Mail
  on the remote host and sets the KB.";

if(description)
{
  script_id(800098);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-01-08 07:43:30 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Kerio Mail Server Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of Kerio Mail Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800098";
SCRIPT_DESC = "Kerio Mail Server Version Detection";

smtpPort = get_kb_item("Services/smtp");
if(!smtpPort){
  smtpPort = 25;
}

imapPort = get_kb_item("Services/imap");
if(!imapPort){
  imapPort = 143;
}

popPort = get_kb_item("Services/pop3");
if(!popPort){
  popPort = 110;
}

foreach port (make_list(smtpPort, imapPort, popPort))
{
  banner = get_kb_item(string("Banner/", port));

  if("Kerio MailServer" >< banner || "Kerio Connect" >< banner)
  {
    kerioVer = eregmatch(pattern:"Kerio (MailServer|Connect) ([0-9.]+)(-| )?([a-zA-Z]+" +
                                 " [0-9]+)?", string:banner);

    if(!isnull(kerioVer[1])) { 
      server = kerioVer[1];
    } else {
      server = "Mail Server";
    }  

    if(kerioVer[2] != NULL)
    {
      if(kerioVer[4] != NULL)
       kerioVer = kerioVer[2] + "." + kerioVer[4];
      else
       kerioVer = kerioVer[2];
    }

    if(kerioVer != NULL)
    {
      kerioVer = ereg_replace(pattern:" ", replace:"", string:kerioVer);
      set_kb_item(name:"KerioMailServer/Ver", value:kerioVer);
      security_note(data:"Kerio " + server  + " version " + kerioVer +
                             " was detected on the host");
     
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:kerioVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:kerio:kerio_mailserver:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}
