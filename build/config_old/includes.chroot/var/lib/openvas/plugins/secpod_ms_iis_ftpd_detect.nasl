##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_ftpd_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Microsoft IIS FTP Server Version Detection
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
################################################################################

include("revisions-lib.inc");
tag_summary = "Detection of Microsoft IIS FTP Server.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900875";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"detection", value:"remote probe");
  script_name("Microsoft IIS FTP Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);

  script_summary("Set KB for the version of Microsoft IIS FTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("secpod_ftp_anonymous.nasl");
  script_require_ports("Services/ftp", 21);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("ftp_func.inc");
include("host_details.inc");
include("version_func.inc");

ftpPort = "";
banner = "";
ver = "";
cpe = NULL;

ftpPort = get_kb_item("Services/ftp");
if(!ftpPort){
  ftpPort = 21;
}

if(!get_port_state(ftpPort)) {
  exit(0);
}

banner = get_ftp_banner(port:ftpPort);
if("Microsoft FTP Service" >< banner)
{
  set_kb_item(name:"MS/IIS-FTP/Installed", value:TRUE);
  ver = eregmatch(pattern:"Microsoft FTP Service \(Version ([0-9.]+)\)",
                  string:banner);
  if(ver[1])
  {
    set_kb_item(name:"MS/IIS-FTP/Ver", value:ver[1]);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:iis_ftp:");
    if(isnull(cpe))
     cpe = 'cpe:/a:microsoft:iis_ftp:';

    register_product(cpe:cpe, location:ftpPort + '/tcp', nvt:SCRIPT_OID, port:ftpPort);
    log_message(data: build_detection_report(app:"Microsoft IIS FTP Server ",
                      version:ver[1], install:ftpPort + '/tcp', cpe:cpe,
                      concluded: ver[0]), port:ftpPort);
  }
}
