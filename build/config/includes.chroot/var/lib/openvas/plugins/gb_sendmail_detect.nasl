###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sendmail_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Sendmail Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
##############################################################################

include("revisions-lib.inc");
tag_summary = "The script will detects the installed version of Sendmail and sets
  the result in KB.";

if(description)
{
  script_id(800608);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sendmail Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets KB for the version of Sendmail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/smtp", 25);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800608";
SCRIPT_DESC = "Sendmail Version Detection";

sendmailPort = get_kb_item("Services/smtp");

if(!sendmailPort){
  sendmailPort = 25;
}

if(!get_port_state(sendmailPort)){
  exit(0);
}

sendMail = get_smtp_banner(port:sendmailPort);

if(sendMail != NULL && "Sendmail" >< sendMail)
{
  sendmailVer = eregmatch(pattern:"ESMTP Sendmail ([0-9.]+)", string:sendMail);
  if(sendmailVer[1] != NULL)
  {
    set_kb_item(name:"SMTP/" + sendmailPort + "/Sendmail", value:sendmailVer[1]);
    security_note(data:"Sendmail version " + sendmailVer[1] + 
                         " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: sendmailVer[1], exp:"^([0-9.]+)",base:"cpe:/a:sendmail:sendmail:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}
