#######################################################################
# OpenVAS Network Vulnerability Test
#
# rsync modules list
#
# LSS-NVT-2009-003
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
#######################################################################

include("revisions-lib.inc");
tag_summary = "This script lists all modules available from particular rsync daemon.

It's based on csprotocol.txt from the rsync source tree.";

if (description) {

    script_id(102003);
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
    script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    script_name("rsync modules list");

    desc = "
    Summary:
    " + tag_summary;
    script_description(desc);
    script_summary("Lists all available rsync modules");
    script_category(ACT_GATHER_INFO);
    script_family("Service detection");
    script_copyright("Copyright (C) 2009 LSS");
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


function rsync_connect() {
    sock = open_sock_tcp(port);
    if (! sock)
        return NULL;

    banner = recv_line(socket : sock, length : 8096);
    send(socket : sock, data : banner);

    # skip MOTD

    for (i = 0; i < motd_lines; ++i)
        recv_line(socket : sock, length : 8096);

    return sock;
}

function get_module_list() {
    sock = rsync_connect();
    if (! sock)
        return NULL;

    num = 0;
    send(socket : sock, data : '#list\r\n');
    while (1) {
        line = recv_line(socket : sock, length : 8096, timeout : 1);
        if (! line || strstr(line, '@RSYNCD'))
            break;

        ret[num++] = line;
    }

    return ret;
}

function authentication_required(module) {
    sock = rsync_connect();
    if (! sock)
        return 'unknown';

    send(socket : sock, data : string(module + '\r\n'));
    line = recv_line(socket : sock, length : 8096);

    if (strstr(line, '@RSYNCD: OK'))
        return 'no';
    else if (strstr(line, '@RSYNCD: AUTHREQD'))
        return 'yes';
    else
        return 'unknown';
}

#------------------------------------------------------------------------------

port = get_kb_item("Services/rsync");

if (! port)
    port = 873; # default

if (! get_port_state(port))
  exit (0);

# Read the banner and motd. Send dummy data to force rsyncd to close
# the connection.

sock = open_sock_tcp(port);
if (! sock)
    exit(0);

send(socket : sock, data : '@RSYNCD: DUMMY\r\n');

banner = recv_line(socket : sock, length : 8096);
while (1) {
    buf = recv_line(socket : sock, length : 8096);
    if (! buf || strstr(buf, '@ERROR'))
        break;

    motd_lines++;
}

set_kb_item(name : "rsync/" + port + "/banner", value : chomp(banner));

# Extract all modules and prepare a report

modules = get_module_list();
if (! modules)
    exit(0);

report = 'Available rsync modules: \n\n';

foreach line (modules) {
    chomp(line);

    ar = split(line, sep : '\t', keep : 0);

    module = chomp(ar[0]);
    dsc    = chomp(ar[1]);
    auth   = authentication_required(module : module);

    report += '  ' + module + '\t(' + dsc + '; authentication: ' + auth + ')\n';
}

security_note(data : report);
