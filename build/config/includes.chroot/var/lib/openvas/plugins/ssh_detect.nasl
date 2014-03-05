# OpenVAS Vulnerability Test
# $Id: ssh_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: SSH Server type and version
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_solution = "Apply filtering to disallow access to this port from untrusted hosts";
tag_summary = "This detects the SSH Server's type and version by connecting to the server
and processing the buffer received.
This information gives potential attackers additional information about the
system they are attacking. Versions and Types should be omitted
where possible.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.10267";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"detection", value:"remote probe");

 script_name("SSH Server type and version");


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("SSH Server type and version");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 script_family("Product detection");
 script_require_keys("Services/ssh");
 script_dependencies("find_service.nasl", "find_service2.nasl", "external_svc_ident.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

CONNECT_LOGIN = "OpenVAS";
CONNECT_PASSWD = "OpenVAS";


#
# The script code starts here
#
include("misc_func.inc");
include("ssh_func.inc");
include("host_details.inc");
include("cpe.inc");


function register_os_version(banner) {
  local_var known_systems, len, i;

  # Order matters, as some banners can include several keywords. Only the
  # first matched entry is kept.
  known_systems = make_list(
      "ubuntu", "cpe:/o:canonical:ubuntu_linux",
      "debian", "cpe:/o:debian:debian_linux",
      "freebsd", "cpe:/o:freebsd:freebsd",
      "openbsd", "cpe:/o:openbsd:openbsd",
      "netbsd", "cpe:/o:netbsd:netbsd",
      "CISCO_WLC","cpe:/o:cisco:wireless_lan_controller",
      "cisco|FIPS User Access Verification", "cpe:/o:cisco",
      "SSH-2.0-Sun","cpe:/o:sun:sunos",
      "SSH-2.0-NetScreen","cpe:/o:juniper:netscreen_screenos",
      "SSH-2.0-xxxxxxx|FortiSSH","cpe/cpe:/o:fortinet:fortios",
      "OpenVMS","cpe:/o:hp:openvms");

  len = max_index(known_systems) - 1;
  for (i = 0; i < len; i += 2) {
    if (eregmatch(string:banner, pattern:known_systems[i], icase:1)) {
      register_host_detail(name:"OS", value:known_systems[i+1],
                           nvt:SCRIPT_OID,
                           desc:"SSH Server type and version");
      break;
    }
  }
}

port = get_kb_item("Services/ssh");

if (!port)
  port = 22;

if (_HAVE_LIBSSH) {
    # The ssh_get_server_banner function will only be available after
    # we switch to libssh 0.6.  Thus for the time being, we use a
    # workaround.
    soc = open_sock_tcp(port);
    if (!soc) {
        if (defined_func("error_message"))
            error_message(port:port,
                  data:"Failed to connect despite port was reported open (1).");
        exit(-1);
    }
    version = ssh_hack_get_server_version(socket:soc);
    close(soc);
}

soc = open_sock_tcp(port);
if (!soc) {
  if (defined_func("error_message"))
    error_message(port:port,
                  data:"Failed to connect despite port was reported open.");
  exit(-1);
}

ssh_login(socket:soc, login:CONNECT_LOGIN, password:CONNECT_PASSWD,
              pub:NULL, priv:NULL, passphrase:NULL);

if (!_HAVE_LIBSSH)
    version   = get_ssh_server_version();
banner    = get_ssh_banner();
supported = get_ssh_supported_authentication();

close(soc);

if (version) {

  set_kb_item(name:"SSH/banner/" + port, value:version);

  text = 'Detected SSH server version: ' + version + '\n';

  register_os_version(banner:version + ' ' + banner);

  text += 'Remote SSH supported authentication: ';
  if (supported) {
    set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
    text += supported + '\n';
  } else {
    text += '(not available)\n';
  }

  text += 'Remote SSH banner: \n';
  if (banner) {
    set_kb_item(name:"SSH/textbanner/" + port, value:banner);
    text += banner + '\n\n';
  } else {
    text += '(not available)\n\n';
  }

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version, exp:"OpenSSH[_ ]([.a-zA-Z0-9]*)[- ]?.*", base:"cpe:/a:openbsd:openssh:");
  if (cpe) {
    register_product(cpe:cpe, location:string(port, "/tcp"), nvt:SCRIPT_OID);
  }
  register_service(port: port, proto: "ssh");
}

text += 'CPE: ' + cpe;
text += '\n\nConcluded from remote connection attempt with credentials:';
text += '\n  Login: ' + CONNECT_LOGIN;
text += '\n  Password: ' + CONNECT_PASSWD;
text += '\n';

log_message(port:port, data:text);
