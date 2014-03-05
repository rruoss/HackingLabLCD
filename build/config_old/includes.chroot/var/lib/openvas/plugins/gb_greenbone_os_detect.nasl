###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect.nasl 68 2013-11-19 12:41:31Z mime $
#
# Greenbone GSM Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "Detection of Greenbone GSM.

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103220";

if (description)
{

 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 68 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-19 13:41:31 +0100 (Tue, 19 Nov 2013) $");
 script_tag(name:"creation_date", value:"2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Greenbone GSM Detection");

 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks if the remote Host is a Greenbone GSM");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 443, "Services/ssh", 22);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

function check_http() {

  local_var port, vers, version, info;

  port = get_http_port(default:443);

  if(get_port_state(port)) {

    url = string("/login/login.html");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>Greenbone Security Assistant" >< buf && "Greenbone OS" >< buf) {

      vers = "unknown";
      version = eregmatch(string: buf, pattern: '<div class="gos_version">Greenbone OS ([^<]+)</div>',icase:FALSE);

      if ( ! isnull(version[1]) ) {

        vers = version[1];
        concluded = version[0];

        _set_kb_entrys_and_report(version:vers);

      }

    }
  }
}

function check_ssh() {

  local_var port, vers, version, info;

  include("ssh_func.inc");

  port = get_kb_item("Services/ssh");

  if (!port) port = 22;
  if (get_port_state(port)) {

    soc = open_sock_tcp(port);
    if (soc ) {

        if(_HAVE_LIBSSH) {
            # We do not need to login to get the banner.  Until we can
            # switch to libssh 0.6 we use our hacked up version.
            # After the switch we may want to have a login function
            # which terminates the connection right before the KEX
            # protocol part.  This will allows us to get the server
            # banner without a need to try a login.
            banner = ssh_hack_get_server_version(socket:soc);
        }
        else {
            user = rand_str(charset:"abcdefghijklmnopqrstuvwxyz", length:8);
            pass = rand();

            ssh_login (socket:soc, login:user, password:pass, pub:NULL,
                       priv:NULL, passphrase:NULL);

            banner = get_ssh_banner ();
        }
        close(soc);

        if(banner && "Greenbone OS" >< banner) {

          version = eregmatch(pattern:"Greenbone OS ([0-9.-]+)",string:banner);

          if( ! isnull(version[1] ) ) {

            vers = version[1];
            concluded = version[0];

	    _set_kb_entrys_and_report(version:vers);

        }
      }
    }
  }
}

function _set_kb_entrys_and_report(version) {

  local_var version;

  set_kb_item(name: string("greenbone/G_OS"), value: version);

  cpe = build_cpe(value:version, exp:"^([0-9.-]+)", base:"cpe:/o:greenbone:greenbone_os:");
  if(isnull(cpe))
    cpe = 'cpe:/o:greenbone:greenbone_os';

  register_host_detail(name:"OS", value:cpe, nvt:SCRIPT_OID, desc:"Greenbone GSM Detection");
  register_host_detail(name:"OS", value:"Greenbone OS", nvt:SCRIPT_OID, desc:"Greenbone GSM Detection");

  log_message(data: build_detection_report(app:"Greenbone OS", version:version, install:port + '/tcp', cpe:cpe, concluded: concluded),
              port:port);

  exit(0);

}


check_ssh();
check_http();

exit(0);
