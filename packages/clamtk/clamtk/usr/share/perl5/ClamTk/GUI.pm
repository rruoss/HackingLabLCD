# ClamTk, copyright (C) 2004-2012 Dave M
#
# This file is part of ClamTk (http://clamtk.sourceforge.net).
#
# ClamTk is free software; you can redistribute it and/or modify it
# under the terms of either:
#
# a) the GNU General Public License as published by the Free Software
# Foundation; either version 1, or (at your option) any later version, or
#
# b) the "Artistic License".
package ClamTk::GUI;

# use strict;
# use warnings;
# Can't use FATAL with warnings here;
# chokes on the readline if the stop button is hit.
$| = 1;

use Cwd 'abs_path';
use File::Copy 'move';
use File::Basename 'basename', 'dirname';
use POSIX 'locale_h',          'strftime';
use Date::Calc 'Delta_Days';
use Digest::MD5 'md5_hex';
use Locale::gettext;
use LWP::UserAgent;
use Encode;
use URI;

use Gtk2;
use Glib 'TRUE', 'FALSE';

# Somebody might complain about the "use bytes" thing,
# but it's the only way I can get the RTL override malware
# thingie to JUST WORK(TM).
use bytes;
binmode( STDIN,  ':encoding(UTF-8)' );
binmode( STDOUT, ':encoding(UTF-8)' );

my $window;    # Top level window

my $directive = '';    # Arguments passed to clamscan
my %dirs_scanned;      # Keeps track of directories scanned for display
my $SCAN;              # Scan handle; must be global for stop button
my $scan_pid;          # Pid of scan handle; must be global for stop button
my $stopped = 1;       # Program is stopped if 1, running if 0
my $found;             # Stores info about possibly infected files
my $gui_tb;            # Easy buttons bar
my $start_time;        # For use with Elapsed time
my $scan_frame;        # Holds the progressbar, files scanned, etc.
my $drop_frame;        # For the drag and drop stuff
my $found_count = 0;   # Number of threats found
my $num_scanned = 0;   # Number of files scanned, clean or bad
my $proxy_status_img;       # Image; global for 'flicker' appearance
my ($scan_status_label);    # Shows what's being scanned, a little more

# A little color never hurt anyone.  Standards be damned.
# my $silver = Gtk2::Gdk::Color->new( 0xCCCC, 0xCCCC, 0xCCCC );
my $white = Gtk2::Gdk::Color->new( 0xFFFF, 0xFFFF, 0xFFFF );

# Last scan label (should be an InfoBar, but can't find it)
my $last_scan_bar = Gtk2::Label->new;

# Scan frame stuff, under the progressbar
my ( $left_status, $mid_status );

# Right-most column
my ( $engine_version_text, $defs_version_text );

# Left-most column - global so we can adjust them throughout
my ( $engine_gui_img, $defs_gui_img, $status_gui_img );

# $stop_btn is global because its tooltips change based on
# whether or not ClamTk is actively scanning
my $stop_btn;

# $loading_img is the spinner button.
my $loading_img;
# Most packagers are going to miss the inclusion of $loading_img,
# or they'll miss the new "images/" directory, so we'll decide
# whether or not to show it based on whether it's where we expect
my $show_loader = 1;

# Assuming images are under /usr/share/pixmaps.  Keeping the
# directory up here so packagers can change it.
my $images_dir = '/usr/share/pixmaps';

# Tooltips
my $tt = '';

my ( $new_slist, $new_hlist );

sub start_gui {
    INIT { Gtk2->init; }    ## no critic

    $tt = Gtk2::Tooltips->new();

    # The main window
    $window = Gtk2::Window->new();
    $window->signal_connect( destroy => sub { Gtk2->main_quit; } );
    $window->set_title( gettext('Virus Scanner') );
    $window->set_border_width(0);
    $window->set_resizable(FALSE);
    $window->set_position('center');
    if ( -e "$images_dir/clamtk.png" ) {
        $window->set_default_icon_from_file("$images_dir/clamtk.png");
    } elsif ( -e "$images_dir/clamtk.xpm" ) {
        $window->set_default_icon_from_file("$images_dir/clamtk.xpm");
    }

    my $vbox = Gtk2::VBox->new( FALSE, 0 );
    $window->add($vbox);

    #<<< Perltidy can ignore this
    # @entries contain the menubar items
    my @entries = (
        ### Everything falls under the following 6 rows ###
        [ 'FileMenu',       undef, gettext('_Scan') ],
        [ 'ViewMenu',       undef, gettext('_View') ],
        [ 'OptionsMenu',    undef, gettext('_Options') ],
        [ 'QuarantineMenu', undef, gettext('_Quarantine') ],
        [ 'AdvancedMenu',   undef, gettext('_Advanced') ],
        [ 'HelpMenu',       undef, gettext('_Help') ],

        ### These fall under "Scan", although it's still called FileMenu. ###
        # Scan a single file
        [   'Scan_File',        undef,
            gettext('A _File'), '<control>F',
            undef, 	sub { ClamTk::GUI->getfile('file') },
	    FALSE
        ],
        # Scan home directory, but do not descend
        [   'Quick_Home', 		undef,
            gettext('Home (_Quick)'), 	'<control>Q',
            undef, 	sub { ClamTk::GUI->getfile('home') },
	    FALSE
        ],
        # Scan home directory, descend (recursive)
        [   'Full_Home', 		undef,
            gettext('Home (Recursive)'), 	'<control>Z',
            undef,	 sub { ClamTk::GUI->getfile('full-home') },
	    FALSE
        ],
        # Scan a single directory
        [   'Scan_Directory', 		undef,
            gettext('A _Directory'), 	'<control>D',
            undef,	sub { ClamTk::GUI->getfile('dir') },
	    FALSE
        ],
        # Scan a directory, descend (recursive)
        [   'Recursive_Scan', 		undef,
            gettext('_Recursive Scan'), '<control>R',
            undef,	sub { ClamTk::GUI->getfile('recur') },
	    FALSE
        ],
        # Scan a device - relies upon udev and /proc/mounts
        [   'Scan_Device', 		undef,
            gettext('A Device'), 	'<control>J', undef,	
			sub { ClamTk::Device->look_for_device($window->get_position) },
	    FALSE
        ],
        # Quit
        [   'Exit',           undef,
            gettext('E_xit'), '<control>X',
            undef,	sub { Gtk2->main_quit },
	    FALSE
        ],

        ### These fall under View ###
        # Show dialog of recorded scans
        [   'ManageHistories', 		undef,
            gettext('Manage _Histories'), "<control>H",
            undef, 	sub { history('delete') },
            FALSE
        ],
        # Show last scan info (date of scan and last infected)
        [   'LastScanInfo', 		undef,
            gettext('_Last Scan Information'), "<control>L",
            undef, 	\&last_scan,
            FALSE
        ],
        # Closes the scan bar, zeroes out everything
        [   'ClearOutput',                undef,
            gettext('Clear _Output'),     '<control>O',
            undef,	\&clear_output,
            FALSE
        ],

        ### These fall under Quarantine ###
        # Simple window showing number of quarantined objects
        [   'Status', 			undef,
	    gettext('_Status'), 	'<control>S',
            undef,	\&quarantine_check,
	    FALSE
        ],
        # Dialog box - delete or return quarantined objects
        [   'Maintenance', 		undef,
            gettext('_Maintenance'), 	'<control>M',
            undef,	\&maintenance,
	    FALSE
        ],
        # Delete quarantined objects
        [   'Empty', 			undef,
            gettext('_Empty Quarantine Folder'), '<control>E',
            undef,	\&del_quarantined,
	    FALSE
        ],

        ### These fall under Help ###
        # Dialog box for Help, to update signatures, check for GUI updates.
        [   'UpdateSig', 			undef,
            gettext('_Check for updates'), 	'<control>U',
	    undef,	sub { ClamTk::Update->update_dialog($window->get_position) },
	    FALSE
        ],
        # Standard About dialog
        [   'About',                          undef,
            gettext("_About"),                '<control>A',
            undef,	\&about,
	    FALSE
        ],

        ### The final four here are for Advanced ###
        # Schedule scans and AV sig updates
        [   'Scheduler', 		undef,
            gettext('_Scheduler'), 	'<control>T', undef,	
		    sub { ClamTk::Schedule->schedule_dialog($window->get_position) },
	    FALSE
        ],
        # Change to/from user updates to system
        [   "AVsetup", 			undef,
            gettext('Rerun antivirus setup _wizard'),
            '<control>W', undef,
            sub { ClamTk::Update->av_db_select($window->get_position) },
	    FALSE
        ],
        # Huge preferences window
        [   'Preferences',          undef,
            gettext('Preferences'), '<control>P',
            undef,	\&preferences,
	    FALSE
        ],
		# Submit a file for analysis
        [   'SubmitFile',          undef,
            gettext('Submit a file for analysis'), '<control>Y',
	    undef,	sub { ClamTk::Submit->analysis($window->get_position) },
	    FALSE
        ],
    );
    #>>>
    # $ui_info dictates where the options fall
    my $ui_info = "<ui>
        <menubar name='MenuBar'>
         <menu action='FileMenu'>
          <menuitem action='Scan_File'/>
          <menuitem action='Scan_Directory'/>
          <menuitem action='Recursive_Scan'/>
          <menuitem action='Quick_Home'/>
          <menuitem action='Full_Home'/>
          <separator/>
          <menuitem action='Scan_Device'/>
          <separator/>
          <menuitem action='Exit'/>
         </menu>
          <menu action='ViewMenu'>
          <menuitem action='ManageHistories'/>
          <menuitem action='LastScanInfo'/>
          <menuitem action='ClearOutput'/>
         </menu>
         <menu action='QuarantineMenu'>
          <menuitem action='Status'/>
          <menuitem action='Maintenance'/>
          <menuitem action='Empty'/>
         </menu>
         <menu action='AdvancedMenu'>
           <menuitem action='Scheduler'/>
           <menuitem action='AVsetup'/>
           <menuitem action='Preferences'/>
           <menuitem action='SubmitFile'/>
 	 </menu>
         <menu action='HelpMenu'>
          <menuitem action='UpdateSig'/>
          <menuitem action='About'/>
         </menu>
        </menubar>
</ui>";

    my $actions = Gtk2::ActionGroup->new('Actions');
    $actions->add_actions( \@entries, undef );

    my $ui = Gtk2::UIManager->new;
    $ui->insert_action_group( $actions, 0 );

    $window->add_accel_group( $ui->get_accel_group );
    $ui->add_ui_from_string($ui_info);
    $vbox->pack_start( $ui->get_widget('/MenuBar'), FALSE, FALSE, 0 );

    # Last scan bar area
    # Shows things like "Please wait..."
    # We have to put it at the top now -
    # sometimes does not show when at the bottom
    # and beginning a scan
    $vbox->pack_start( $last_scan_bar, FALSE, FALSE, 2 );

    # Actions Frame
    # These are for easy access to buttons for scanning

    #my $gui_frame = Gtk2::Frame->new( gettext('Actions') );
    my $gui_frame = Gtk2::Frame->new();
    $vbox->pack_start( $gui_frame, FALSE, FALSE, 0 );
    $gui_frame->set_shadow_type('none');

    my $gui_box = Gtk2::VBox->new( TRUE, 5 );
    $gui_frame->add($gui_box);

    # Now that Gnome has decided to not show the images
    # in buttons by default, the regular buttons looked pretty stupid.
    # We'll fix the new packing problem by changing the buttonbox
    # to a toolbar and using those buttons.  Nice try, Gnome.
    # The toolbar ($gui_tb) is global so we can change its style
    # from the Preferences dialog.
    $gui_tb = Gtk2::Toolbar->new;
    $gui_tb->set_style('both');
    $gui_tb->set_show_arrow(FALSE);

    # Button for quick home folder scan
    my $home_img = Gtk2::ToolButton->new_from_stock('gtk-home');
    $home_img->set_expand(TRUE);
    $home_img->set_label( gettext('Home') );
    $home_img->signal_connect( clicked => sub { ClamTk::GUI->getfile('home') }
    );
    $tt->set_tip( $home_img, gettext('Scan your home directory') );
    $gui_tb->insert( $home_img, -1 );

    $gui_tb->insert( Gtk2::SeparatorToolItem->new, -1 );

    # Button for histories
    my $hist_img = Gtk2::ToolButton->new_from_stock('gtk-edit');
    $hist_img->set_expand(TRUE);
    $hist_img->set_label( gettext('Histories') );
    $hist_img->signal_connect( clicked => sub { history('delete') } );
    $tt->set_tip( $hist_img, gettext('View your previous scans') );
    $gui_tb->insert( $hist_img, -1 );

    $gui_tb->insert( Gtk2::SeparatorToolItem->new, -1 );

    # Button for preferences
    my $pref_img = Gtk2::ToolButton->new_from_stock('gtk-preferences');
    $pref_img->set_expand(TRUE);
    $pref_img->set_label( gettext('Preferences') );
    $pref_img->signal_connect( clicked => \&preferences );
    $tt->set_tip( $pref_img, gettext('Set or view your preferences') );
    $gui_tb->insert( $pref_img, -1 );

    $gui_tb->insert( Gtk2::SeparatorToolItem->new, -1 );

    # Button to exit
    my $quit_img = Gtk2::ToolButton->new_from_stock('gtk-quit');
    $quit_img->set_expand(TRUE);
    $quit_img->set_label( gettext('Exit') );
    $quit_img->signal_connect( clicked => sub { Gtk2->main_quit } );
    $tt->set_tip( $quit_img, gettext('Exit this program') );
    $gui_tb->insert( $quit_img, -1 );

    $gui_box->pack_start( $gui_tb, TRUE, TRUE, 0 );

    # Status frame:
    # This shows versions of ClamAV, ClamTk, signatures,
    # date of last scan, date of last infected file

    #my $status_frame = Gtk2::Frame->new( gettext('Status') );
    my $status_frame = Gtk2::Frame->new('		');
    $vbox->pack_start( $status_frame, FALSE, FALSE, 5 );
    $status_frame->set_shadow_type('none');

    my $status_table = Gtk2::Table->new( 3, 3, FALSE );
    $status_frame->add($status_table);

    # Version of ClamTk
    my $status_gui_box   = Gtk2::HBox->new( TRUE, 0 );
    my $gui_text         = Gtk2::Label->new( gettext('GUI version') );
    my $gui_version_text = Gtk2::Label->new( ClamTk::App->get_TK_version() );
    $status_gui_img =
        Gtk2::Image->new_from_stock( 'gtk-yes', 'small-toolbar' );
    $tt->set_tip( $status_gui_img, gettext('Current') );
    $status_gui_box->pack_start( $status_gui_img,   TRUE, TRUE, 0 );
    $status_gui_box->pack_start( $gui_text,         TRUE, TRUE, 0 );
    $status_gui_box->pack_start( $gui_version_text, TRUE, TRUE, 0 );
    $status_table->attach_defaults( $status_gui_box, 0, 3, 0, 1 );

    # Date of antivirus signatures
    my $defs_gui_box = Gtk2::HBox->new( TRUE, 0 );
    my $defs_text = Gtk2::Label->new( gettext('Antivirus definitions') );
    $defs_version_text = Gtk2::Label->new( gettext('Unknown') );
    $defs_gui_img = Gtk2::Image->new_from_stock( 'gtk-yes', 'small-toolbar' );
    $tt->set_tip( $defs_gui_img, gettext('Current') );
    $defs_gui_box->pack_start( $defs_gui_img,      TRUE, TRUE, 0 );
    $defs_gui_box->pack_start( $defs_text,         TRUE, TRUE, 0 );
    $defs_gui_box->pack_start( $defs_version_text, TRUE, TRUE, 0 );
    $status_table->attach_defaults( $defs_gui_box, 0, 3, 1, 2 );

    # Version of ClamAV
    my $engine_gui_box = Gtk2::HBox->new( TRUE, 0 );
    my $engine_text = Gtk2::Label->new( gettext('Antivirus engine') );
    $engine_version_text = Gtk2::Label->new( gettext('Unknown') );
    $engine_gui_img =
        Gtk2::Image->new_from_stock( 'gtk-info', 'small-toolbar' );
    $tt->set_tip( $engine_gui_img, gettext('Version') );
    $engine_gui_box->pack_start( $engine_gui_img,      TRUE, TRUE, 0 );
    $engine_gui_box->pack_start( $engine_text,         TRUE, TRUE, 0 );
    $engine_gui_box->pack_start( $engine_version_text, TRUE, TRUE, 0 );
    $status_table->attach_defaults( $engine_gui_box, 0, 3, 2, 3 );

    # Scan frame:
    # This holds the progressbar and keeps track of files
    # scanned, viruses found and the status/elapsed time

    #$scan_frame = Gtk2::Frame->new( gettext('Scan') );
    $scan_frame = Gtk2::Frame->new();
    $vbox->pack_start( $scan_frame, FALSE, FALSE, 10 );

    my $scan_box = Gtk2::VBox->new();
    $scan_frame->modify_bg( 'normal', $white );
    $scan_frame->add($scan_box);

    $scan_status_label = Gtk2::Label->new('');
    $scan_status_label->set_justify('center');
    $scan_status_label->set_ellipsize('middle');

    my $scan_table = Gtk2::Table->new( 1, 3, FALSE );
    $scan_box->pack_start( $scan_table, FALSE, FALSE, 0 );

    $scan_table->attach( $scan_status_label, 0, 1, 0, 1, [ 'fill', 'expand' ],
        ['shrink'], 0, 0 );

    if ( -e "$images_dir/clamtk-loader.gif" ) {
        $loading_img =
            Gtk2::Image->new_from_file("$images_dir/clamtk-loader.gif");
        $scan_table->attach( $loading_img, 1, 2, 0, 1, [ 'shrink', 'shrink' ],
            ['shrink'], 0, 0 );
        $show_loader = 1;
    } else {
        $loading_img = Gtk2::Image->new_from_stock( 'gtk-missing-image',
            'small-toolbar' );
        $scan_table->attach( $loading_img, 1, 2, 0, 1, [ 'shrink', 'shrink' ],
            ['shrink'], 0, 0 );
        $show_loader = 0;
    }

    my $stop_image =
        Gtk2::Image->new_from_stock( 'gtk-stop', 'small-toolbar' );
    $stop_btn = Gtk2::Button->new();
    $stop_btn->set_property( image => $stop_image );
    $stop_btn->set_relief('none');
    $tt->set_tip( $stop_btn, gettext('Stop scanning now') );
    $scan_table->attach( $stop_btn, 2, 3, 0, 1, [ 'shrink', 'shrink' ],
        ['shrink'], 0, 0 );
    $stop_btn->signal_connect(
        'clicked' => sub {
            clear_output(), return if ($stopped);
            $loading_img->hide()
                if ( $loading_img->visible );

            kill 15, $scan_pid + 1;
            waitpid( $scan_pid + 1, 0 ) if ( $scan_pid + 1 );
            kill 15, $scan_pid if ($scan_pid);
            waitpid( $scan_pid, 0 ) if ($scan_pid);
            please_wait();

            my $loop = Glib::MainLoop->new;
            Glib::Timeout->add(
                2000,
                sub {
                    $loop->quit;
                    FALSE;
                } );
            $loop->run;

            # this close returns the stupid readline() error.
            # not sure how to fix it yet, besides commenting
            # out 'use warnings' :) it's the only way to immediately
            # stop the $SCAN so far...
            close($SCAN);    # or warn "Unable to close scanner! $!\n";
            $scan_status_label->set_text('');
            $last_scan_bar->set_text('');
            $last_scan_bar->hide();
            $stopped = 1;
        } );

    my $bottom_box = Gtk2::HBox->new( FALSE, 0 );
    $scan_box->pack_start( $bottom_box, FALSE, FALSE, 0 );

    $left_status = Gtk2::Label->new( gettext('Files Scanned: ') );
    $bottom_box->pack_start( $left_status, TRUE, TRUE, 5 );

    $mid_status = Gtk2::Label->new( gettext('Threats Found: ') );
    $bottom_box->pack_start( $mid_status, TRUE, TRUE, 5 );

    # Drag-n-drop frame
    $drop_frame = Gtk2::Frame->new();
    $vbox->pack_start( $drop_frame, TRUE, TRUE, 2 );
    my $dropbox = Gtk2::EventBox->new;
    $dropbox->modify_bg( 'normal', $white );
    $drop_frame->add($dropbox);
    my $droplabel = Gtk2::Label->new;
    $droplabel->set_markup( "<span foreground = '#FFFFFF' size='medium'>"
            . gettext('Drag and drop')
            . "</span>" );
    $dropbox->add($droplabel);
    $dropbox->signal_connect(
        'enter-notify-event' => sub {
            $droplabel->set_markup(
                      "<span foreground = '#CCCCCC' size='medium'>"
                    . gettext('Drag and drop')
                    . "</span>" );
        } );
    $dropbox->signal_connect(
        'leave-notify-event' => sub {
            $droplabel->set_markup(
                      "<span foreground = '#FFFFFF' size='medium'>"
                    . gettext('Drag and drop')
                    . "</span>" );
        } );

    $dropbox->drag_dest_set( [ 'drop', 'motion', 'highlight' ],
        [ 'copy', 'private', 'default', 'move', 'link', 'ask' ] );
    $dropbox->signal_connect(
        drag_data_received => sub {
            my ( $widget, $context, $widget_x, $widget_y, $data, $info,
                $time )
                = @_;
            my $u     = URI->new( $data->data );
            my $upath = $u->file;
            #$upath =~ s|%([0-9a-zA-Z]{2})|chr(hex($1))|ge;
            #$upath =~ s|file://(.*?)|$1|;
            if ( -e $upath ) {
                ClamTk::GUI->getfile( 'cmd-scan', $upath );
            }
        } );

    my $target_list = Gtk2::TargetList->new();
    my $atom        = Gtk2::Gdk::Atom->new("text/uri-list");
    $target_list->add( $atom, 0, 0 );
    $dropbox->drag_dest_set_target_list($target_list);

    $window->set_focus_child($stop_btn);
    $window->show_all();
    $scan_frame->hide;
    $last_scan_bar->hide;

    # The only reason we take @ARGV is for right-click scanning,
    # not arguments (e.g., -v).
    please_wait();
    if (@ARGV) {
        update_status_frame();
        if ( -d $ARGV[0] ) {
            my $d = abs_path( $ARGV[0] );
            if ( not $d ) {    # no permissions
                $found->{$found_count}->{name} = $ARGV[0];
                $found->{$found_count}->{status} =
                    gettext('Could not scan (permissions)');
                $found->{$found_count}->{action} = gettext('None');
                $found_count++;
                ClamTk::Results->display($found);
                clean_up('cmd-scan');
            } elsif ( $ARGV[0] =~ m#^/(proc|sys|dev)# ) {
                $found->{$found_count}->{name} = $ARGV[0];
                $found->{$found_count}->{status} =
                    gettext('Directory excluded from scan');
                $found->{$found_count}->{action} = gettext('None');
                $found_count++;
                ClamTk::Results->display($found);
                clean_up('cmd-scan');
            } else {
                ClamTk::GUI->getfile( 'cmd-scan', $d );
            }
        } else {
            my $pos = 0;
            my @send;
            for my $f (@ARGV) {
                $f = abs_path($f);
                next if ( $f =~ m#^/(proc|sys|dev)#
                    or not -r $f );
                push( @send, $f );
            }
            #ClamTk::GUI->getfile( 'cmd-scan', @ARGV );
            ClamTk::GUI->getfile( 'cmd-scan', @send );
        }
    } else {
        update_status_frame();
    }

    # Quick check for 'crontab'.
    # Disable this shortcut if it doesn't exist.
    # This kind of disabling doesn't disable the Ctrl- shortcut.
    my $crontab =
          ( -e '/usr/bin/crontab' )       ? '/usr/bin/crontab'
        : ( -e '/usr/local/bin/crontab' ) ? '/usr/local/bin/crontab'
        : ( -e '/bin/crontab' )           ? '/bin/crontab'
        :                                   '';
    chomp($crontab);
    if ( !$crontab ) {
        warn "crontab not installed - disabling Scheduler\n";
        my $del = $ui->get_widget('/MenuBar/AdvancedMenu/Scheduler');
        $del->set_sensitive(FALSE);
    }

    # Quick check for 'udevinfo' or 'udevadm'.
    # Disable this shortcut if it doesn't exist.
    # This kind of disabling doesn't disable the Ctrl- shortcut.
    local $ENV{'PATH'} = '/bin:/usr/bin:/sbin';
    delete @ENV{ 'IFS', 'CDPATH', 'ENV', 'BASH_ENV' };
    my $path  = '';
    my $which = 'which';
    my $adm   = 'udevadm';

    if ( open( my $c, '-|', $which, $adm ) ) {
        while (<$c>) {
            chomp;
            $path = $_ if ( -e $_ );
        }
    }

    if ( !$path ) {
        $adm = 'udevinfo';
        if ( open( my $c, '-|', $which, $adm ) ) {
            while (<$c>) {
                chomp;
                $path = $_ if ( -e $_ );
            }
        }
    }

    if ( !$path ) {
        warn "udev not installed - disabling Device scan\n";
        my $del = $ui->get_widget('/MenuBar/FileMenu/Scan_Device');
        $del->set_sensitive(FALSE);
    }

    # Launch!
    Gtk2->main();

    return $window;
}

sub update_status_frame {
    # This is useful as its own subroutine so we
    # can call it from anywhere
    Gtk2->main_iteration while ( Gtk2->events_pending );

    # ClamAV version
    $engine_version_text->set_text( ClamTk::App->get_AV_version() );

    # ClamTk version
    Gtk2->main_iteration while ( Gtk2->events_pending );

    my ($ret) = ClamTk::Update->update_gui('startup');
    if ( $ret == 5 ) {
        $status_gui_img->set_from_stock( 'gtk-dialog-question',
            'small-toolbar' );
        $tt->set_tip( $status_gui_img, gettext('Unable to check') );
    } elsif ( $ret == 1 || $ret == 3 ) {
        $status_gui_img->set_from_stock( 'gtk-yes', 'small-toolbar' );
        $tt->set_tip( $status_gui_img, gettext('Current') );
    } else {
        $status_gui_img->set_from_stock( 'gtk-no', 'small-toolbar' );
        $tt->set_tip( $status_gui_img,
            gettext('A newer version is available') );
    }
    Gtk2->main_iteration while ( Gtk2->events_pending );

    # Signatures
    set_sig_status();

    $last_scan_bar->set_text('');
    $last_scan_bar->hide();
    return;
}

sub set_sig_status {
    if ( !$defs_version_text ) {
        # This may get called from Update.pm directly
        # and so may not yet exist
        $defs_version_text = Gtk2::Label->new;
    }
    if ( !$defs_gui_img ) {
        # This may get called from Update.pm directly
        # and so may not yet exist
        $defs_gui_img = Gtk2::Image->new;
    }

    my $sig_date = ClamTk::App->get_date_sigs();
    if ( !$sig_date ) {
        $defs_version_text->set_text( gettext('None found') );
    }

    my ( $d, $m, $y ) = split / /, $sig_date;
    my $date_ret = date_diff( $d, $m, $y );

    if ( $date_ret eq 'outdated' || !$sig_date ) {
        $defs_gui_img->set_from_stock( 'gtk-no', 'small-toolbar' );
        $defs_version_text->set_text( gettext('Outdated') );
        $tt->set_tip( $defs_gui_img,
            gettext('Your antivirus signatures are out-of-date') );
    } else {
        $defs_gui_img->set_from_stock( 'gtk-yes', 'small-toolbar' );
        $defs_version_text->set_text( gettext('Current') );
        $tt->set_tip( $defs_gui_img, gettext('Current') );
    }
    $tt->set_tip( $defs_version_text,
        $sig_date ? $sig_date : gettext('Unknown') );
    $window->queue_draw;
    Gtk2->main_iteration while ( Gtk2->events_pending );
    return;
}

sub set_tk_status {
    my ( undef, $ret ) = @_;

    if ( $ret == 4 || $ret == 5 ) {
        $status_gui_img->set_from_stock( 'gtk-dialog-question',
            'small-toolbar' );
        $tt->set_tip( $status_gui_img, gettext('Unable to check') );
    } elsif ( $ret == 1 || $ret == 3 ) {
        $status_gui_img->set_from_stock( 'gtk-yes', 'small-toolbar' );
        $tt->set_tip( $status_gui_img, gettext('Current') );
    } else {
        $status_gui_img->set_from_stock( 'gtk-no', 'small-toolbar' );
        $tt->set_tip( $status_gui_img,
            gettext('A newer version is available') );
    }
    Gtk2->main_iteration while ( Gtk2->events_pending );
    $window->queue_draw;
    return;
}

sub date_diff {
    my ( $day2, $month2, $year2 ) = @_;
    my ( $day1, $month1, $year1 ) = split / /,
        strftime( '%d %m %Y', localtime );
    my %months = (
        'Jan' => '01',
        'Feb' => '02',
        'Mar' => '03',
        'Apr' => '04',
        'May' => '05',
        'Jun' => '06',
        'Jul' => '07',
        'Aug' => '08',
        'Sep' => '09',
        'Oct' => 10,
        'Nov' => 11,
        'Dec' => 12,
        );
    return unless ( $day2 && $month2 && $year2 );

    my $diff = Delta_Days( $year1, $month1, $day1, $year2, $month2, $day2 );
    $diff *= -1;

    # Number of days old
    if ( $diff >= 4 ) {
        return 'outdated';
    } else {
        return 'current';
    }
}

sub getfile {
    shift;    # throw away package name

    # $option will be either "home", "full-home", "file", "dir",
    # "recur", "cmd-scan" or "device"
    my ($option) = shift;
    my @cmd_input = @_;

    my $paths = ClamTk::App->get_path('all');
    my %prefs = ClamTk::Prefs->get_all_prefs();

    my @scans;    # file(s)/path(s) sent to clamscan
    $directive = '';    # arguments sent to clamscan

    # Don't bother doing anything if clamscan can't be found
    warn "Cannot scan without clamscan!\n" unless $paths->{clampath};
    return unless $paths->{clampath};

    Gtk2->main_iteration while ( Gtk2->events_pending );
    clear_output();
    chdir( $paths->{directory} ) or chdir('/tmp');

    my ( $dir, $dialog );
    Gtk2->main_iteration while ( Gtk2->events_pending );

    # By default, we ignore .gvfs directories.
    # Once we figure out KDE's process, we'll include that too.
    if ( !ClamTk::Prefs->get_preference('Mounted') ) {
        # This returned a '0', so filter the results
        for my $m (qw(.gvfs smb4k)) {
            $directive .= " --exclude-dir=$m";
        }
    }

    for my $ignore (
        split(
            /;/,
            ClamTk::Prefs->get_preference('Whitelist')
                . $paths->{whitelist_dir} )
        ) {
        # For clamscan, we'll stick with the full path:
        my $full = $ignore;
        # We just want the base directory name for F::F::R:
        $ignore = ( split( '/', $ignore ) )[-1];
        $directive .= " --exclude-dir=$full";
    }

    # Remove mail directories for now -
    # until we can parse them... sigh.
    # http://clamtk.sourceforge.net/faq.html#inbox .
    # Not all of these can be appended to $HOME for a more
    # specific path - kmail (e.g.) is somewhere under $HOME/.kde/blah/foo/...
    my @maildirs = qw(
        .thunderbird	.mozilla-thunderbird
        Mail	kmail
        );
    for my $mailbox (@maildirs) {
        $directive .= " --exclude-dir=$mailbox";
    }

    # A more descriptive title based on what we're after
    my $title =
          ( $option eq 'file' ) ? gettext('Select File')
        : ( $option eq 'dir' && !$prefs{Recursive} )
        ? gettext('Select a Directory (directory scan)')
        : ( $option eq 'recur' or $prefs{Recursive} )
        ? gettext('Select a Directory (recursive scan)')
        : '';

    # The ever-popular home directory scan
    if ( $option eq 'home' ) {
        push( @scans, $paths->{directory} );
        if ( !$prefs{Recursive} ) {
            $directive .= ' --max-dir-recursion=1';
        } elsif ( $prefs{Recursive} ) {
            $directive .= ' --recursive';
        }
        $window->queue_draw;
        please_wait();
        $window->queue_draw;
        Gtk2->main_iteration while ( Gtk2->events_pending );
    } elsif ( $option eq 'file' ) {
        $dialog = Gtk2::FileChooserDialog->new(
            gettext($title), $window, 'open',
            'gtk-cancel' => 'cancel',
            'gtk-ok'     => 'ok',
            );
        $dialog->set_select_multiple(TRUE);
        $dialog->set_position('center-on-parent');
        if ( "ok" eq $dialog->run ) {
            please_wait();
            $window->queue_draw;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            push( @scans, $dialog->get_filenames );
            $dialog->destroy;
            $window->queue_draw;
        } else {
            $dialog->destroy;
            return;
        }
    } elsif ( $option eq 'device' ) {
        my $dir = $cmd_input[0];
        return if ( not $dir or not -d $dir );
        Gtk2->main_iteration while ( Gtk2->events_pending );
        push( @scans, $dir );
    } elsif ( $option eq 'full-home' ) {
        please_wait();
        Gtk2->main_iteration while ( Gtk2->events_pending );
        push( @scans, $paths->{directory} );
        $directive .= ' --recursive';
    } elsif ( $option eq 'dir' or $option eq 'recur' ) {
        $dialog = Gtk2::FileChooserDialog->new(
            gettext($title), $window,
            'select-folder',
            'gtk-cancel' => 'cancel',
            'gtk-ok'     => 'ok',
            );
        $dialog->set_position('center-on-parent');
        if ( "ok" eq $dialog->run ) {
            $dir = $dialog->get_filename;
            if ( $dir =~ m{^/(proc|sys|dev)}
                or not -r $dir ) {
                $dialog->destroy;
                $found->{$found_count}->{name} = $dir;
                $found->{$found_count}->{status} =
                    ( not -r $dir )
                    ? gettext('Could not scan (permissions)')
                    : gettext('Will not scan that directory');
                $found->{$found_count}->{action} = gettext('None');
                $found_count++;
                ClamTk::Results->display($found);
                clean_up('permissions');
                return;
            }
            please_wait();
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $window->queue_draw;
            $dialog->destroy;
            $window->queue_draw;
            $dir ||= $paths->{directory};
            Gtk2->main_iteration while ( Gtk2->events_pending );

            push( @scans, $dir );

            if ( !$prefs{Recursive} ) {
                if ( $option ne 'recur' ) {
                    $directive .= ' --max-dir-recursion=1';
                }
            } elsif ( $prefs{Recursive} ) {
                $directive .= ' --recursive';
            }

            if ( $option eq 'recur' ) {
                $directive .= ' --recursive';
            }

        } else {
            $dialog->destroy;
            return;
        }
    } elsif ( $option eq 'cmd-scan' ) {
        if ( $cmd_input[0] && -d $cmd_input[0] ) {
            please_wait();
            $window->queue_draw;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            push( @scans, $cmd_input[0] );
            if ( !$prefs{Recursive} ) {
                $directive .= ' --max-dir-recursion=1';
            } elsif ( $prefs{Recursive} ) {
                $directive .= ' --recursive';
            }
        } else {
            please_wait();
            $window->queue_draw;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            for (@cmd_input) {
                push( @scans, $_ );    # if ( -f $_ );
            }
            $directive .= ' --max-dir-recursion=1';
        }
    } else {
        warn "Unknown option '$option'.\n";
    }

    # Can take a minute for clamscan to get going...
    please_wait();

    # close the drag and drop frame
    $drop_frame->hide();
    # open the scan frame for display
    $scan_frame->show();
    $loading_img->hide() if ( $loading_img->visible );

    Gtk2->main_iteration while ( Gtk2->events_pending );

    $tt->set_tip( $stop_btn, gettext('Stop scanning now') );

    # start the timer - replaces the "Ready"
    $start_time = time if ( !$start_time );

    # we'll count this as ! $stopped
    $stopped = 0;

    # reset %$found
    $found = {};

    # These lines are for 'thorough'. :)
    # If it's selected, we add detection for both
    # potentially unwanted applications and broken executables.
    if ( $prefs{Thorough} ) {
        $directive .= ' --detect-pua --detect-broken';
    } else {
        $directive =~ s/\s--detect-pua --detect-broken//;
    }

    # only a single file
    if ( $option eq 'file' ) {
        scan( $directive, @scans );
    } else {
        # Pass the files to the filter first
        filter($option);

        # By default, 20Mb is the largest we go -
        # unless the preference is to ignore size.
        if ( !$prefs{SizeLimit} ) {
            $directive .= ' --max-filesize=20M';
        }

        scan( $directive, @scans );
    }
    clean_up();
}

sub filter {
    my ($opt) = shift;

    my $paths = ClamTk::App->get_path('all');

    # remove the hidden files if chosen:
    if (   !ClamTk::Prefs->get_preference('ScanHidden')
        && $opt ne 'recur'
        && $opt ne 'full-home' ) {
        $directive .= ' --exclude="\/\."';
    }

    # symlinks:
    # The symlink stuff from clamscan requires >= 0.97.
    my ($version) = ClamTk::App->get_AV_version();
    # Ensure it's just digits and dots:
    $version =~ s/[^0-9\.]//g;
    if (   ( $version cmp '0.97' ) == 0
        || ( $version cmp '0.97' ) == 1 ) {
        $directive .= ' --follow-dir-symlinks=1';
        $directive .= ' --follow-file-symlinks=1';
    }
}

sub scan {
    # $directive = options passed to clamscan
    # @get		 = list of files/paths sent to clamscan
    my ( $directive, @get ) = @_;
    @get = map { quotemeta($_) } @get;
    $window->queue_draw;

    # Leave if we have no direct files or directory to scan
    return if ( !@get );

    my $paths   = ClamTk::App->get_path('all');
    my $command = $paths->{clamscan};

    # Use the user's sig db if it's selected
    if ( ClamTk::Prefs->get_preference('Update') eq 'single' ) {
        $command .= " --database=$paths->{db}";
    }

    # implicit fork; gives us the PID of clamscan so we can
    # kill it if the user hits the Stop button
    $scan_pid = open( $SCAN, '-|', "$command $directive @get 2>&1" );
    defined($scan_pid) or die "couldn't fork: $!\n";

    # Using ':encoding(utf8)' screws with BiDi text
    # binmode( $SCAN, ':encoding(utf8)' );
    # Adding the ":bytes" layer prevents CentOS
    # from choking on the BiDi text.  Doesn't seem necessary
    # for some distros.
    binmode( $SCAN, ':utf8:bytes' );

    # pulse  = mode we're in; activity or blank
    # pulser = Glib::Timeout; gets removed after scan
    # iter   = used for pulsing every other file
    my ( $pulse, $pulser, $iter );
    $pulse = ClamTk::Prefs->get_preference('PulseMode');
    if ( $pulse eq 'activity' ) {
        $pulser = Glib::Timeout->add(
            100,
            sub {
                timer();
                $window->queue_draw;
                Gtk2->main_iteration while Gtk2->events_pending;
                return TRUE;
            } );
    } else {
        $iter = 0;
    }

    Gtk2->main_iteration while Gtk2->events_pending;
    while (<$SCAN>) {
        Gtk2->main_iteration while Gtk2->events_pending;

        # Show our spinner
        $loading_img->show()
            if ( !$loading_img->visible && $show_loader );

        next if (/^LibClamAV/);
        next if (/^\s*$/);
        $last_scan_bar->set_text('');
        $last_scan_bar->hide();

        my ( $file, $status );
        if (/(.*?): ([^:]+) FOUND/) {
            $file   = $1;
            $status = $2;
        } elsif (/(.*?): (OK)$/) {
            $file   = $1;
            $status = $2;
        }    #     else {
             #    	warn "something else: file = <$file>, stat = <$status>\n";
             #}

        # Ensure the file is still there (things get moved)
        # and that it got scanned
        next unless ( $file && -e $file && $status );
        next if ( $status =~ /module failure/ );

        chomp($file)   if ( defined $file );
        chomp($status) if ( defined $status );
        $scan_status_label->set_text( sprintf gettext('Scanning %s...'),
            dirname($file) );

        # Lots of temporary things under /tmp/clamav;
        # we'll just ignore them.
        $dirs_scanned{ dirname($file) } = 1
            unless ( dirname($file) =~ /\/tmp\/clamav/
            || dirname($file) eq '.' );

        # Do not show files in archives - we just want the end-result.
        # It still scans and we still show the result.
        next if ( $file =~ /\/tmp\/clamav/ );

        # $status is the "virus" name.
        $status =~ s/\s+FOUND$//;

        # If we're not in activity mode, pulse every other file.
        # You'll go blind looking at that thing going back and forth.
        if ( !$pulse ) {
            if ( $iter % 2 ) {
                timer();
            }
            $iter++;
        }

        # These aren't necessarily clean (despite the variable's name)
        # - we just don't want them counted as viruses
        my $clean_words = join( '|',
            'OK',
            'Zip module failure',
            "RAR module failure",
            'Encrypted.RAR',
            'Encrypted.Zip',
            'Empty file',
            'Excluded',
            'Input/Output error',
            'Files number limit exceeded',
            'handler error',
            'Broken.Executable',
            'Oversized.Zip',
            'Symbolic link' );

        if ( $status !~ /$clean_words/ ) {    # a virus
            $found->{$found_count}->{name}   = $file;
            $found->{$found_count}->{status} = $status;
            $found->{$found_count}->{action} = gettext('None');
            $found_count++;
        }

        # If we have possible threats, highlight it with bold.
        if ( $found_count > 0 ) {
            $mid_status->set_markup(
                sprintf gettext('<b>Threats Found: %d</b>'), $found_count );
        } else {
            $mid_status->set_text( sprintf gettext('Threats Found: %d'),
                $found_count );
        }
        $num_scanned++;

        Gtk2->main_iteration while ( Gtk2->events_pending );
        timer() if ( !$pulse );
    }

    please_wait();
    Gtk2->main_iteration while ( Gtk2->events_pending );
    if ( !$pulse ) {
        timer();
    } else {
        Glib::Source->remove($pulser) if ($pulse);
    }
    $loading_img->hide();

    # Done scanning - close filehandle and return to
    # getfile() and then to clean-up
    close($SCAN);    # or warn "Unable to close scanner! $!\n";
}

sub clear_output {
    # Return if there are files still being scanned
    return if ( !$stopped );

    # Clear the text
    $last_scan_bar->set_text('');
    $last_scan_bar->hide();
    $scan_status_label->set_text('');

    # Refresh the main window
    $window->queue_draw;

    # Reset the bottom labels
    $left_status->set_text( gettext('Files Scanned: ') );
    $mid_status->set_text( gettext('Threats Found: ') );

    # Hide the scanning frame
    $scan_frame->hide();

    # Show the drag and drop frame
    $drop_frame->show_all();
    Gtk2->main_iteration while ( Gtk2->events_pending );
    $window->queue_draw;
    return;
}

sub timer {
    Gtk2->main_iteration while ( Gtk2->events_pending );
    $left_status->set_text( sprintf gettext('Files Scanned: %d'),
        $num_scanned );
    $window->queue_draw;
    return TRUE;
}

sub clean_up {
    Gtk2->main_iteration while ( Gtk2->events_pending );
    $window->queue_draw;

    $tt->set_tip( $stop_btn, gettext('Close window') );

    # No files scanned?
    if ( $num_scanned == 0 ) {
        $last_scan_bar->set_markup( "<span background = '#FFFFC8'>"
                . gettext('No files were scanned.')
                . "</span>" );
        $last_scan_bar->show_all();
    }

    # Only show the please_wait if files were scanned.
    # Otherwise the 'no files scanned' will immediately be removed.
    $window->queue_draw;
    Gtk2->main_iteration while ( Gtk2->events_pending );

    my $db_total = ClamTk::App->get_num_sigs();
    my $REPORT;    # filehandle for histories log
    my ( $mon, $day, $year ) = split / /, strftime( '%b %d %Y', localtime );

    # And now we can hide it because we have the info.
    if ($num_scanned) {
        $last_scan_bar->hide();
    }

    # Save date of scan
    if ( $found_count > 0 ) {
        ClamTk::Prefs->set_preference( 'LastInfection', "$day $mon $year" );
        $window->queue_draw;
    }

    $window->queue_draw;
    Gtk2->main_iteration while ( Gtk2->events_pending );

    my %prefs = ClamTk::Prefs->get_all_prefs();

    my $paths     = ClamTk::App->get_path('history');
    my $virus_log = $paths . "/" . "$mon-$day-$year" . ".log";

    # sort the directories scanned for display
    my @sorted = sort { $a cmp $b } keys %dirs_scanned;
    #if ( open $REPORT, '>>:encoding(UTF-8)', $virus_log ) {
    if ( open $REPORT, '>>', $virus_log ) {
        print $REPORT "\nClamTk, v", ClamTk::App->get_TK_version(), "\n",
            scalar localtime, "\n";
        print $REPORT sprintf gettext("ClamAV Signatures: %d\n"), $db_total;
        print $REPORT gettext("Directories Scanned:\n");
        for my $list (@sorted) {
            print $REPORT "$list\n";
        }
        printf $REPORT gettext("\nFound %d possible %s (%d %s scanned).\n\n"),
            $found_count,
            $found_count == 1 ? gettext('threat') : gettext('threats'),
            $num_scanned,
            $num_scanned == 1 ? gettext('file') : gettext('files');
    } else {
        $scan_status_label->set_text(
            gettext('Could not write to logfile. Check permissions.') );
    }

    $db_total =~ s/(\w+)\s+$/$1/;
    $scan_status_label->set_text(
        sprintf gettext('Scanning complete (%d signatures)'), $db_total );
    $left_status->set_text( sprintf gettext('Files Scanned: %d'),
        $num_scanned );
    if ( $found_count != 0 ) {
        $mid_status->set_markup( sprintf gettext('<b>Threats Found: %d</b>'),
            $found_count );
    }
    $window->queue_draw;

    # Set the minimum sizes for the two columns,
    # the filename and its status - if we're saving a log.
    my $lsize = 20;
    my $rsize = 20;
    if ( $found_count == 0 ) {
        print $REPORT gettext("No threats found.\n");
    } else {
        # Now get the longest lengths of the column contents.
        for my $length ( sort keys %$found ) {
            $lsize =
                ( length( $found->{$length}->{name} ) > $lsize )
                ? length( $found->{$length}->{name} )
                : $lsize;
            $rsize =
                ( length( $found->{$length}->{status} ) > $rsize )
                ? length( $found->{$length}->{status} )
                : $rsize;
        }
        # Set a buffer which is probably unnecessary.
        $lsize += 5;
        $rsize += 5;
        # Print to the log:
        for my $num ( sort keys %$found ) {
            printf $REPORT "%-${lsize}s %-${rsize}s\n",
                $found->{$num}->{name}, $found->{$num}->{status};
        }
    }

    print $REPORT '-' x ( $lsize + $rsize + 5 ), "\n";
    close($REPORT);

    # If threats are found, show the Results window.
    if ($found_count) {
        ClamTk::Results->display($found);
    }

    # reset things
    $num_scanned  = 0;
    $found_count  = 0;
    %dirs_scanned = ();
    $stopped      = 1;
    $start_time   = '';
    $directive    = '';
}

sub show_message_dialog {
    my ( $parent, $type, $button, $message ) = @_;

    my $dialog;
    $dialog =
        Gtk2::MessageDialog->new_with_markup( $parent,
        [qw(modal destroy-with-parent)],
        $type, $button, $message );

    $dialog->run;
    $dialog->destroy;
    return;
}

sub maintenance {
    my $main_win = Gtk2::Dialog->new;
    $main_win->signal_connect( destroy => sub { $main_win->destroy; } );
    $main_win->set_default_size( 400, 200 );
    $main_win->set_title( gettext('Quarantine') );
    $main_win->move( window_coords() );

    my $new_vbox = Gtk2::VBox->new( FALSE, 0 );
    $main_win->get_content_area()->add($new_vbox);

    my $paths   = ClamTk::App->get_path('viruses');
    my @q_files = glob "$paths/*";
    my $s_win   = Gtk2::ScrolledWindow->new;
    $s_win->set_shadow_type('none');
    $s_win->set_policy( 'automatic', 'automatic' );
    $new_vbox->pack_start( $s_win, TRUE, TRUE, 0 );

    $new_slist = Gtk2::SimpleList->new( gettext('File') => 'text', );
    $s_win->add($new_slist);

    my $new_bar = Gtk2::Toolbar->new;
    $new_vbox->pack_start( $new_bar, FALSE, FALSE, 0 );
    $new_bar->set_style('both-horiz');

    my $restore_btn = Gtk2::ToolButton->new_from_stock('gtk-undelete');
    $restore_btn->set_is_important(TRUE);
    $restore_btn->set_label( gettext('Restore') );
    $new_bar->insert( $restore_btn, -1 );
    $restore_btn->signal_connect(
        clicked => sub { restore( \@q_files ), 'false_pos' } );

    my $del_pos_btn = Gtk2::ToolButton->new_from_stock('gtk-delete');
    $del_pos_btn->set_is_important(TRUE);
    $new_bar->insert( $del_pos_btn, -1 );
    $del_pos_btn->signal_connect(
        clicked => sub { main_del_pos( \@q_files ), 'delete' } );

    my $m_sep = Gtk2::SeparatorToolItem->new;
    $m_sep->set_draw(FALSE);
    $m_sep->set_expand(TRUE);
    $new_bar->insert( $m_sep, -1 );

    my $pos_quit_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $pos_quit_btn->set_is_important(TRUE);
    $new_bar->insert( $pos_quit_btn, -1 );
    $pos_quit_btn->signal_connect( clicked => sub { $main_win->destroy } );

    for my $opt (@q_files) {
        push @{ $new_slist->{data} }, basename($opt);
    }

    $main_win->show_all;
}

sub restore {
    my ($q_ref) = @_;
    my @sel = $new_slist->get_selected_indices;
    return if ( !@sel );

    my $paths = ClamTk::App->get_path('all');

    my $deref     = $sel[0];
    my $data      = $new_slist->{data}[$deref];
    my $top_dir   = $paths->{viruses} .= "/";
    my $tdata     = encode( 'utf8', $data->[0] );
    my $full_path = $top_dir .= $tdata;
    return if ( not exists $data->[0] );

    my $md5 = get_md5($full_path);
    return if ( !$md5 );

    # By default, the final destination will be $HOME
    my $final_destination = $paths->{directory} . '/';

    # We should have a record of the quarantined file
    # so we can return it - its path and permissions:
    my ( $path, $perm ) = ClamTk::Prefs->restore( $md5, 'exists' );
    if ( !$path ) {
        # We didn't receive a path for this file, so
        # by default it's going $HOME
        $path = $final_destination . $tdata;
    }

    if ($path) {
        if ( -e $path ) {
            # Another file by that name already exists
            $final_destination = $path .= '.restore';
        } else {
            # We can set the given path to our final destination
            $final_destination = $path;
        }
    } else {
        # We have nothing to go on, so it's going $HOME
        #$final_destination .= $data->[0];
        $final_destination .= $tdata;
    }

    # Move it back
    move( $full_path, $final_destination ) or do {
        show_message_dialog( $window, 'warning', 'ok',
            "Couldn't move file to $final_destination: $!\n" );
        return;
    };

    # If we obtained permissions, apply them; or, 644 by default. (?)
    # Unless someone has a better idea for default perms.
    $perm ||= 644;
    chmod oct($perm), $final_destination;

    # If it's still in the original location, something blew up:
    if ( -e $full_path ) {
        show_message_dialog( $window, 'error', 'ok',
            gettext('Operation failed.') );
        return;
    }

    # Update restore file: remove the file from it:
    ClamTk::Prefs->restore( $md5, 'remove' );

    # Remove the file from view:
    splice @{ $new_slist->{data} }, $deref, 1;

    # Show a success message:
    my $msg = sprintf gettext('Restored as %s.'), $final_destination;
    show_message_dialog( $window, 'info', 'ok', $msg );

    # Get a fresh listing of quarantined files
    @$q_ref = glob "$paths->{viruses}/*";
}

sub main_del_pos {
    my ($q_ref) = @_;
    my @sel = $new_slist->get_selected_indices;
    return if ( !@sel );
    my $deref = $sel[0];
    my $data  = $new_slist->{data}[$deref];

    my $paths = ClamTk::App->get_path('viruses');

    my $top_dir = $paths . "/";
    my $full_path = $top_dir .= $data->[0];
    return if ( !-e $full_path );

    my $md5 = get_md5($full_path);

    # Update restore file: remove the file from it
    ClamTk::Prefs->restore( $md5, 'remove' );

    # Delete the file
    unlink $full_path or do {
        show_message_dialog( $window, 'warning', 'ok', "Couldn't delete ",
            $data->[0], "\n" );
    };
    if ( -e $full_path ) {
        show_message_dialog( $window, 'error', 'ok',
            gettext('Operation failed.') );
        return;
    }

    # Remove the file from view
    splice @{ $new_slist->{data} }, $deref, 1;

    # Get a fresh listing of files
    @$q_ref = glob "$paths/*";
}

sub quarantine_check {
    my $paths = ClamTk::App->get_path('viruses');
    if ( !-d $paths ) {
        show_message_dialog( $window, 'error', 'close',
            gettext('No virus directory available.') );
        return;
    }
    my @trash;
    unless ( opendir( DIR, $paths ) ) {
        show_message_dialog( $window, 'error', 'close',
            gettext('Unable to open the virus directory.') );
        return;
    }
    @trash = grep { -f "$paths/$_" } readdir(DIR);
    closedir(DIR);
    my $del = scalar(@trash);
    if ( !$del ) {
        show_message_dialog( $window, 'info', 'ok',
            gettext('No items currently quarantined.') );
    } else {
        my $notice = sprintf gettext('%d item(s) currently quarantined.'),
            $del;
        show_message_dialog( $window, 'info', 'ok', $notice );
    }
}

sub del_quarantined {
    my $paths = ClamTk::App->get_path('viruses');
    unless ( -e $paths ) {
        show_message_dialog( $window, 'error', 'close',
            gettext('There is no quarantine directory to empty.') );
        return;
    } else {
        my $confirm_message = gettext('Really delete all quarantined files?');
        my $confirm =
            Gtk2::MessageDialog->new( $window,
            [qw(modal destroy-with-parent)],
            'question', 'ok-cancel', $confirm_message );

        if ( 'cancel' eq $confirm->run ) {
            $confirm->destroy;
            return;
        } else {
            $confirm->destroy;
            my @trash;
            unless ( opendir( DIR, $paths ) ) {
                show_message_dialog( $window, 'error', 'close',
                    gettext('Unable to open the virus directory.') );
                return;
            }
            @trash = grep { -f "$paths/$_" } readdir(DIR);
            closedir(DIR);
            if ( scalar(@trash) == 0 ) {
                show_message_dialog( $window, 'info', 'close',
                    gettext('There are no quarantined items to delete.') );
            } else {
                my $del = 0;
                foreach my $f (@trash) {
                    my $full_path = $paths . "/";
                    $full_path .= $f;
                    my $md5 = get_md5($full_path);

                    # update restore file: remove the file from it
                    # if it exists there
                    ClamTk::Prefs->restore( $md5, 'remove' );
                    unlink $full_path and $del++;
                }
                my $notice = sprintf gettext('Removed %d item(s).'), $del;
                show_message_dialog( $window, 'info', 'close', $notice );
            }
        }
    }
}

sub history {
    my $paths   = ClamTk::App->get_path('history');
    my @h_files = glob "$paths/*.log";
    if ( scalar(@h_files) > 1 ) {
        @h_files = history_sort(@h_files);
    }
    my $new_win = Gtk2::Dialog->new( gettext('Scanning Histories'),
        $window, 'destroy-with-parent' );
    $new_win->set_default_size( 400, 200 );

    my $top_dir = $paths . "/";
    my $sortnum = 0;              # 0 = asc, 1 = desc

    my $new_vbox = Gtk2::VBox->new;
    $new_win->get_content_area()->add($new_vbox);

    my $s_win = Gtk2::ScrolledWindow->new;
    $s_win->set_shadow_type('none');
    $s_win->set_policy( 'automatic', 'automatic' );
    $new_vbox->pack_start( $s_win, TRUE, TRUE, 0 );

    $new_hlist = Gtk2::SimpleList->new( gettext('Histories') => 'text' );
    $s_win->add($new_hlist);
    $new_hlist->set_headers_clickable(TRUE);
    $new_hlist->get_column(0)->signal_connect(
        clicked => sub {
            $sortnum ^= 1;
            for my $p (@h_files) {
                last if ( $p =~ /\.log$/ );
                $p .= '.log';
            }
            splice @{ $new_hlist->{data} }, 0, scalar(@h_files);
            my %cache;
            my @sort_this;
            if ( !$sortnum ) {
                @sort_this = sort {
                    ( $cache{$a} ||= -M $a ) <=> ( $cache{$b} ||= -M $b )
                } @h_files;
            } else {
                @sort_this = sort {
                    ( $cache{$b} ||= -M $b ) <=> ( $cache{$a} ||= -M $a )
                } @h_files;
            }
            for (@sort_this) {
                s/(.*?)\.log$/$1/;
                push @{ $new_hlist->{data} }, basename($_);
            }
        } );

    my $new_bar = Gtk2::Toolbar->new;
    $new_vbox->pack_start( $new_bar, FALSE, FALSE, 0 );
    $new_bar->set_style('both-horiz');

    my $hist_view = Gtk2::ToolButton->new_from_stock('gtk-select-all');
    $hist_view->set_is_important(TRUE);
    $hist_view->set_label( gettext('View') );
    $new_bar->insert( $hist_view, -1 );
    $hist_view->signal_connect(
        clicked => sub {
            view_box( $new_win->get_position );
        } );

    my $n_sep = Gtk2::SeparatorToolItem->new;
    $n_sep->set_draw(FALSE);
    $n_sep->set_expand(TRUE);
    $new_bar->insert( $n_sep, -1 );

    my $pos_quit = Gtk2::ToolButton->new_from_stock('gtk-close');
    $pos_quit->set_is_important(TRUE);
    $new_bar->insert( $pos_quit, -1 );
    $pos_quit->signal_connect( clicked => sub { $new_win->destroy } );

    my $del_single = Gtk2::ToolButton->new_from_stock('gtk-delete');
    $del_single->set_is_important(TRUE);
    $new_bar->insert( $del_single, -1 );
    $del_single->signal_connect(
        clicked => sub { history_del_single( \@h_files ) } );

    for my $opt (@h_files) {
        $opt =~ s/\.log//;
        push @{ $new_hlist->{data} }, basename($opt);
    }

    $new_win->move( window_coords() );
    $new_win->show_all;
    return;
}

sub history_sort {
    # It's not the Schwartzian Transform, but
    # it's my first Orcish Maneuver.
    my %orcish;
    return
        sort { ( $orcish{$a} ||= -M $a ) <=> ( $orcish{$b} ||= -M $b ) } @_;
}

sub history_del_single {
    my ($h_ref) = @_;
    my @sel = $new_hlist->get_selected_indices;
    return if ( !@sel );
    my $deref = $sel[0];
    my $data  = $new_hlist->{data}[$deref];

    my $history = ClamTk::App->get_path('history');

    my $top_dir   = $history . "/";
    my $full_path = $top_dir . $data->[0] . '.log';
    return if ( !-e $full_path );

    unlink $full_path or do {
        show_message_dialog( $window, 'warning', 'ok',
            "Could not delete " . $data->[0] . "\n" );
    };
    if ( -e $full_path ) {
        my $notice = sprintf gettext('Unable to delete %s!'), $data->[0];
        show_message_dialog( $window, 'error', 'ok', $notice );
        return;
    }
    splice @{ $new_hlist->{data} }, $deref, 1;
    @$h_ref = glob "$history/*";

    return;
}

sub view_box {
    my ( $x, $y ) = @_;
    my @sel = $new_hlist->get_selected_indices;
    return if ( !@sel );

    my $paths = ClamTk::App->get_path('history');

    my $deref     = $sel[0];
    my $data      = $new_hlist->{data}[$deref];
    my $full_path = $paths . "/" . $data->[0] . '.log';
    return if ( !-e $full_path );

    my $view_win =
        Gtk2::Dialog->new( sprintf( gettext('Viewing %s'), $data->[0] ),
        undef, [qw( modal destroy-with-parent )] );
    #$view_win->set_default_response('close');
    $view_win->signal_connect( response => sub { $view_win->destroy } );
    $view_win->set_default_size( 800, 350 );
    $view_win->move( $x, $y );

    my $textview = Gtk2::TextView->new;
    $textview->set( editable       => FALSE );
    $textview->set( cursor_visible => FALSE );

    my $FILE;    # filehandle for histories log
    unless ( open( $FILE, '<:encoding(UTF-8)', $full_path ) ) {
        my $notice = sprintf gettext('Problems opening %s...'), $data->[0];
        show_message_dialog( $window, 'error', 'ok', $notice );
        return;
    }
    my $text;
    $text = do {
        local $/ = undef;
        $text = <$FILE>;
    };
    close($FILE)
        or warn sprintf gettext("Unable to close FILE %s! %s\n"),
        $data->[0];

    my $textbuffer = $textview->get_buffer;
    # I hate setting a font here, but it makes the printf stuff
    # look MUCH better.
    $textbuffer->create_tag( 'mono', family => 'Monospace' );
    $textbuffer->insert_with_tags_by_name( $textbuffer->get_start_iter, $text,
        'mono' );

    my $scroll_win = Gtk2::ScrolledWindow->new;
    $scroll_win->set_border_width(5);
    $scroll_win->set_shadow_type('none');
    $scroll_win->set_policy( 'automatic', 'automatic' );

    $view_win->vbox->pack_start( $scroll_win, TRUE, TRUE, 0 );
    $scroll_win->add($textview);

    my $viewbar = Gtk2::Toolbar->new;
    $view_win->vbox->pack_start( $viewbar, FALSE, FALSE, 0 );
    $viewbar->set_style('both-horiz');

    my $v_sep = Gtk2::SeparatorToolItem->new;
    $v_sep->set_draw(FALSE);
    $v_sep->set_expand(TRUE);
    $viewbar->insert( $v_sep, -1 );

    my $close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $close_btn->set_is_important(TRUE);
    $viewbar->insert( $close_btn, -1 );
    $close_btn->signal_connect( clicked => sub { $view_win->destroy } );

    $view_win->show_all();
    return;
}

sub preferences {
    my %prefs = ClamTk::Prefs->get_all_prefs();

    my $pref =
        Gtk2::Dialog->new( gettext('Preferences'), $window,
        'destroy-with-parent', );
    $pref->signal_connect( destroy => sub { $pref->destroy } );

    my ( $x, $y ) = window_coords();
    $pref->move( $x, $y );

    my $box = Gtk2::VBox->new( FALSE, 0 );
    $pref->get_content_area()->add($box);
    $box->grab_focus;

    my $nb = Gtk2::Notebook->new;
    $nb->set_scrollable(TRUE);
    $nb->set_show_border(TRUE);
    $nb->can_focus(FALSE);
    $nb->set( 'enable-popup' => TRUE );

    my $scan_table = Gtk2::Table->new( 4, 1, TRUE );
    $nb->insert_page( $scan_table, gettext('Scanning Preferences'), 0 );

    my $hidden_box = Gtk2::CheckButton->new_with_label(
        gettext('Scan files beginning with a dot (.*)') );
    $hidden_box->set_active(TRUE) if ( $prefs{ScanHidden} );
    $scan_table->attach_defaults( $hidden_box, 0, 1, 0, 1 );
    $hidden_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'ScanHidden',
                $hidden_box->get_active ? 1 : 0 );
        } );
    $hidden_box->can_focus(FALSE);

    my $recur_box = Gtk2::CheckButton->new_with_label(
        gettext('Scan all files and directories within a directory') );
    $recur_box->set_active(TRUE) if ( $prefs{Recursive} );
    $scan_table->attach_defaults( $recur_box, 0, 1, 1, 2 );
    $recur_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'Recursive',
                $recur_box->get_active ? 1 : 0 );
        } );
    $recur_box->can_focus(FALSE);

    my $deep_box = Gtk2::CheckButton->new_with_label(
        gettext('Enable extra scan settings') );
    $deep_box->set_active(TRUE) if ( $prefs{Thorough} );
    $scan_table->attach_defaults( $deep_box, 0, 1, 2, 3 );
    $deep_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'Thorough',
                $deep_box->get_active ? 1 : 0 );
        } );
    $deep_box->can_focus(FALSE);

    my $size_box = Gtk2::CheckButton->new_with_label(
        gettext('Scan files larger than 20 MB') );
    $size_box->set_active(TRUE) if ( $prefs{SizeLimit} );
    $scan_table->attach_defaults( $size_box, 0, 1, 3, 4 );
    $size_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'SizeLimit',
                $size_box->get_active ? 1 : 0 );
        } );
    $size_box->can_focus(FALSE);

    my $mounted_box = Gtk2::CheckButton->new_with_label(
        # We're sprintf-ing this so that %s can
        # expand to KIO or whatever KDE uses and it
        # won't require a translation change
        sprintf gettext('Scan samba-related directories %s'), "(gvfs, smb4k)"
        );
    $mounted_box->set_active(TRUE) if ( $prefs{Mounted} );
    $scan_table->attach_defaults( $mounted_box, 0, 1, 4, 5 );
    $mounted_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'Mounted',
                $mounted_box->get_active ? 1 : 0 );
        } );
    $mounted_box->can_focus(FALSE);

    my $startup_table = Gtk2::Table->new( 3, 1, TRUE );
    $nb->insert_page( $startup_table, gettext('Startup Preferences'), 1 );

    my $gui_box =
        Gtk2::CheckButton->new_with_label( gettext('Check for GUI updates') );
    $gui_box->set_active(TRUE) if ( $prefs{GUICheck} );
    $startup_table->attach_defaults( $gui_box, 0, 1, 0, 1 );
    $gui_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'GUICheck',
                $gui_box->get_active ? 1 : 0 );
        } );
    $gui_box->can_focus(FALSE);

    my $gui_delete_box = Gtk2::CheckButton->new_with_label(
        gettext('Remove duplicate signature databases') );
    $gui_delete_box->set_active(TRUE) if ( $prefs{DupeDB} );
    $startup_table->attach_defaults( $gui_delete_box, 0, 1, 1, 2 );
    $gui_delete_box->signal_connect(
        toggled => sub {
            ClamTk::Prefs->set_preference( 'DupeDB',
                $gui_delete_box->get_active ? 1 : 0 );
        } );

    my $gui_spacer1 = Gtk2::Label->new();
    $startup_table->attach_defaults( $gui_spacer1, 0, 1, 2, 3 );
    $gui_delete_box->can_focus(FALSE);

    my $whitebox = Gtk2::VBox->new( FALSE, 0 );
    $nb->insert_page( $whitebox, gettext('Whitelist'), 2 );

    # First, we'll need what the user already has set:
    my $user_whitelist   = ClamTk::Prefs->get_preference('Whitelist');
    my $system_whitelist = ClamTk::App->get_path('whitelist_dir');

    my $s_win = Gtk2::ScrolledWindow->new;
    $s_win->set_shadow_type('etched-in');
    $s_win->set_policy( 'automatic', 'automatic' );
    $whitebox->pack_start( $s_win, TRUE, TRUE, 0 );

    my $ex_slist = Gtk2::SimpleList->new( gettext('Directory') => 'text', );
    $s_win->add($ex_slist);
    push @{ $ex_slist->{data} }, $_ for split /;/, $user_whitelist;

    my $ex_bar = Gtk2::HButtonBox->new;
    $ex_bar->set_layout('end');
    $whitebox->pack_start( $ex_bar, FALSE, FALSE, 0 );

    my $add_btn = Gtk2::Button->new_from_stock('gtk-add');
    $ex_bar->add($add_btn);
    $add_btn->signal_connect(
        clicked => sub {
            my $dir    = '';
            my $dialog = Gtk2::FileChooserDialog->new(
                gettext('Select a Directory'), undef,
                'select-folder',
                'gtk-cancel' => 'cancel',
                'gtk-ok'     => 'ok',
                );
            if ( "ok" eq $dialog->run ) {
                $dir = $dialog->get_filename;
                if ( $dir eq "/" ) {

                    # Just in case someone clicks the root (/).
                    $dialog->destroy;
                    return;
                }

                # See if it's already included...
                if ( !grep {/^$dir$/} split /;/,
                    $user_whitelist . $system_whitelist ) {

                    # If not, add to GUI...
                    push @{ $ex_slist->{data} }, $dir;

                    # then add to user's prefs...
                    ClamTk::Prefs->set_preference( 'Whitelist',
                        $user_whitelist . "$dir;" );

                    # ...and refresh the whitelist
                    $user_whitelist =
                        ClamTk::Prefs->get_preference('Whitelist');
                }
            }
            $dialog->destroy;
        } );

    my $del_btn = Gtk2::Button->new_from_stock('gtk-delete');
    $ex_bar->add($del_btn);
    $del_btn->signal_connect(
        clicked => sub {
            my @sel = $ex_slist->get_selected_indices;
            return unless (@sel);
            my $deref  = $sel[0];
            my $remove = $ex_slist->{data}[$deref][0] . ';';

            # refresh our whitelist
            $user_whitelist = ClamTk::Prefs->get_preference('Whitelist');

            # yank the selected from the whitelist
            $user_whitelist =~ s/$remove//;

            # save the whitelist
            ClamTk::Prefs->set_preference( 'Whitelist', $user_whitelist );

            # remove it from the GUI
            splice @{ $ex_slist->{data} }, $deref, 1;
        } );

    my $big_proxy = Gtk2::VBox->new( FALSE, 5 );
    $nb->insert_page( $big_proxy, gettext('Proxy settings'), 3 );

    my $no_proxy_box = Gtk2::VBox->new;
    $big_proxy->pack_start( $no_proxy_box, FALSE, FALSE, 0 );
    my $proxy_btn = Gtk2::RadioButton->new( undef, gettext('No Proxy') );
    $no_proxy_box->pack_start( $proxy_btn, FALSE, FALSE, 0 );

    my $sys_proxy_box = Gtk2::VBox->new;
    $big_proxy->pack_start( $sys_proxy_box, FALSE, FALSE, 0 );
    my $sys_btn =
        Gtk2::RadioButton->new( $proxy_btn, gettext('Environment settings') );
    $sys_proxy_box->pack_start( $sys_btn, FALSE, FALSE, 0 );

    my $manual_proxy_box = Gtk2::VBox->new;
    $big_proxy->pack_start( $manual_proxy_box, FALSE, FALSE, 0 );
    my $man_btn =
        Gtk2::RadioButton->new( $proxy_btn, gettext('Set manually') );
    $manual_proxy_box->pack_start( $man_btn, FALSE, FALSE, 0 );

    my $man_table = Gtk2::Table->new( 3, 3, TRUE );
    $manual_proxy_box->pack_start( $man_table, FALSE, FALSE, 0 );
    $man_table->set_row_spacings(5);

    my $ip_label   = Gtk2::Label->new( gettext('IP address or host:') );
    my $ip_example = Gtk2::Label->new('(e.g., proxy.domain.com)');

    # We can't go with max_length(IP address) because they
    # can insert a hostname here as well. 63 should be enough for anyone.
    my $ip_box = Gtk2::Entry->new_with_max_length(63);
    $ip_box->signal_connect(
        'insert-text' => sub {
            my ( $widget, $string, $position ) = @_;

            # http://www.ietf.org/rfc/rfc1738.txt
            if ( $string !~ m#[\w\.\-\+/:\@\#]# ) {
                $ip_box->signal_stop_emission_by_name('insert-text');
            }
            return;
        } );

    my $port_label   = Gtk2::Label->new( gettext('Port:') );
    my $port_example = Gtk2::Label->new('(e.g., 8080)');
    my $port_box     = Gtk2::SpinButton->new_with_range( 1, 65535, 1 );
    $port_box->set_value(8080);

    $man_table->attach_defaults( $ip_label,   0, 1, 0, 1 );
    $man_table->attach_defaults( $ip_example, 1, 2, 0, 1 );
    $man_table->attach( $ip_box, 2, 3, 0, 1, [ 'expand', 'expand' ],
        ['shrink'], 0, 0 );

    $man_table->attach_defaults( $port_label,   0, 1, 1, 2 );
    $man_table->attach_defaults( $port_example, 1, 2, 1, 2 );
    $man_table->attach( $port_box, 2, 3, 1, 2, [ 'shrink', 'shrink' ],
        ['shrink'], 0, 0 );

    $proxy_btn->signal_connect(
        toggled => sub {
            $ip_box->set_sensitive(FALSE)   if ( $proxy_btn->get_active );
            $port_box->set_sensitive(FALSE) if ( $proxy_btn->get_active );
        } );
    $sys_btn->signal_connect(
        toggled => sub {
            $ip_box->set_sensitive(FALSE)   if ( $sys_btn->get_active );
            $port_box->set_sensitive(FALSE) if ( $sys_btn->get_active );
        } );
    $man_btn->signal_connect(
        toggled => sub {
            if ( $man_btn->get_active ) {
                $ip_box->set_sensitive(TRUE);
                $port_box->set_sensitive(TRUE);
            }
        } );

    # proxy_btn_bar contains the (status_btn)/apply/clear buttons
    my $proxy_btn_bar = Gtk2::HButtonBox->new;
    $big_proxy->pack_start( $proxy_btn_bar, FALSE, FALSE, 0 );
    $proxy_btn_bar->set_layout('end');

    my $p_sep = Gtk2::SeparatorToolItem->new;
    $p_sep->set_draw(FALSE);
    $p_sep->set_expand(TRUE);
    $proxy_btn_bar->add($p_sep);

    # will be hidden shortly after being added
    $proxy_status_img = Gtk2::Image->new;

    my $proxy_apply_btn = Gtk2::Button->new_from_stock('gtk-apply');
    $proxy_apply_btn->signal_connect(
        clicked => sub {
            my $choice;
            if ( $sys_btn->get_active ) {
                $choice = 1;
            } elsif ( $man_btn->get_active ) {
                $choice = 2;
            } else {
                $choice = 0;
            }
            if ( $choice == 0 || $choice == 1 ) {
                if ( ClamTk::Prefs->set_preference( 'HTTPProxy', $choice ) ) {
                    proxy_non_block_status('yes');
                } else {
                    proxy_non_block_status('no');
                }
            }

            if ( $man_btn->get_active ) {
                if ( length( $ip_box->get_text ) < 1 ) {
                    $proxy_btn->set_active(TRUE);
                    return;
                }
                my $ip = $ip_box->get_text;
                if ( $ip !~ m#://# ) {
                    $ip = 'http://' . $ip;
                }
                my $port = $port_box->get_value_as_int;
                if ( $port =~ /^(\d+)$/ ) {
                    $port = $1;
                } else {
                    $port = 8080;
                }

                # Hate to pull in LWP::UserAgent just for this,
                # but we need to sanity check it before they get
                # to using it in the first place
                eval {
                    my $ua = LWP::UserAgent->new;
                    $ua->proxy( http => "$ip:$port" );
                };
                if ($@) {
                    proxy_non_block_status('no');
                    $ip_example->set_markup(
                        qq(<span underline="error" underline_color="red">(e.g., proxy.domain.com)</span>)
                        );
                    return;
                }
                $ip_example->set_text('(e.g., proxy.domain.com)');
                if (   ClamTk::Prefs->set_preference( 'HTTPProxy', $choice )
                    && ClamTk::Prefs->set_proxy( $ip, $port ) ) {
                    proxy_non_block_status('yes');
                    $ip_box->set_text($ip);
                } else {
                    proxy_non_block_status('no');
                    $ip_box->set_text($ip);
                }
            }
        } );

    my $proxy_clear_btn = Gtk2::Button->new_from_stock('gtk-clear');
    $proxy_clear_btn->signal_connect(
        clicked => sub {
            $ip_box->set_text('');
            $port_box->set_text('');
            $proxy_btn->set_active(TRUE);
            $ip_example->set_text('(e.g., proxy.domain.com)');
            if ( ClamTk::Prefs->set_preference( 'HTTPProxy', 0 ) ) {
                proxy_non_block_status('yes');
            } else {
                proxy_non_block_status('no');
            }
        } );

    $proxy_btn_bar->add($proxy_status_img);
    $proxy_btn_bar->add($proxy_apply_btn);
    $proxy_btn_bar->add($proxy_clear_btn);

    # What does the user have set?
    # 0 = no proxy, 1 = env_proxy and 2 = manual proxy

    $ip_box->set_sensitive(FALSE);
    $port_box->set_sensitive(FALSE);

    my $setting = ClamTk::Prefs->get_preference('HTTPProxy');
    if ( !$setting ) {
        $proxy_btn->set_active(TRUE);
    } elsif ( $setting == 1 ) {
        $sys_btn->set_active(TRUE);
    } elsif ( $setting == 2 ) {
        $man_btn->set_active(TRUE);
    }
    my $path = ClamTk::App->get_path('db');
    $path .= '/local.conf';

    if ( -f $path ) {
        if ( open( my $FH, '<', $path ) ) {
            while (<$FH>) {
                chomp;
                my $set;
                if (/HTTPProxyServer\s+(.*?)$/) {
                    $set = $1;
                    if ( $set !~ m#://# ) {
                        $set = 'http://' . $set;
                    }
                    $ip_box->set_text($set);
                    if ( !$setting || $setting == 1 ) {
                        $ip_box->set_sensitive(FALSE);
                    }
                }
                if (/HTTPProxyPort\s+(.*?)$/) {
                    $port_box->set_value($1);
                    if ( !$setting || $setting == 1 ) {
                        $port_box->set_sensitive(FALSE);
                    }
                }
            }
            close($FH);
        }
    }

    $box->pack_start( $nb, TRUE, TRUE, 0 );

    # This toolbar shows up at the bottom of the notebook (nb).
    # Besides the close button, the forward and back buttons allow
    # for fast scrolling through the tabs.
    # What's great is that the way it's written, it will
    # never* have to be updated.
    # * Not a guarantee.
    my $scroll = Gtk2::Toolbar->new;
    $box->pack_start( $scroll, FALSE, FALSE, 5 );
    $scroll->set_style('both-horiz');

    # The four lines here push the buttons to the end.
    # Not only looks better but keeps the look consistent.
    my $sep = Gtk2::SeparatorToolItem->new;
    $sep->set_draw(FALSE);
    $sep->set_expand(TRUE);
    $scroll->insert( $sep, -1 );

    # We don't need to set_label for these buttons because
    # they're stock and the right phrasing.
    my $prev_btn = Gtk2::ToolButton->new_from_stock('gtk-go-back');
    $prev_btn->set_is_important(TRUE);
    $scroll->insert( $prev_btn, -1 );
    $prev_btn->signal_connect(
        clicked => sub {
            if ( $nb->get_current_page == 0 ) {
                $nb->set_current_page( $nb->get_n_pages - 1 );
            } else {
                $nb->prev_page;
            }
        } );

    $scroll->insert( Gtk2::SeparatorToolItem->new, -1 );

    my $next_btn = Gtk2::ToolButton->new_from_stock('gtk-go-forward');
    $next_btn->set_is_important(TRUE);
    $scroll->insert( $next_btn, -1 );
    $next_btn->signal_connect(
        clicked => sub {
            if ( $nb->get_current_page == ( $nb->get_n_pages - 1 ) ) {
                $nb->set_current_page(0);
            } else {
                $nb->next_page;
            }
        } );

    $scroll->insert( Gtk2::SeparatorToolItem->new, -1 );

    my $close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $close_btn->set_is_important(TRUE);
    $scroll->insert( $close_btn, -1 );
    $close_btn->signal_connect( clicked => sub { $pref->destroy } );

    $pref->show_all();
    $proxy_status_img->hide;
    return;
}

sub proxy_non_block_status {
    # This is a non-blocking way to show success or failure
    # in the proxy configuration dialog.
    # I think muppet came up with this.
    my $status = shift;
    $proxy_status_img->set_from_stock(
        ( $status eq 'yes' ) ? 'gtk-yes' : 'gtk-no',
        'small-toolbar' );
    $proxy_status_img->show;
    my $loop = Glib::MainLoop->new;
    Glib::Timeout->add(
        1000,
        sub {
            $loop->quit;
            FALSE;
        } );
    $loop->run;
    $proxy_status_img->hide;
    return;
}

sub window_coords {
    return $window->get_position;
}

sub last_scan {
    my $last_scan      = ClamTk::App->lastscan();
    my $last_infection = ClamTk::Prefs->get_preference('LastInfection');
    $last_scan_bar->show_all();

    # We're trying to mimic the InfoBar color here...
    # Doesn't seem quite right yet, but it works for now.
    # Would be much easier to use it, but apparently it's
    # not packaged in perl-Gtk2 anymore?

    for my $q (qw ( 1 2)) {
        $last_scan_bar->set_markup(
            ( $q == 1 )
            ? "<span background = '#FFFFC8'>"
                . ( sprintf gettext('Date of your last scan: %s'),
                $last_scan )
                . "</span>"
            : "<span background = '#FFFFC8'>"
                . (
                sprintf gettext('Date of last known threat: %s'),
                $last_infection
                )
                . "</span>"
                );

        my $loop = Glib::MainLoop->new;
        Glib::Timeout->add(
            3000,
            sub {
                $loop->quit;
                FALSE;
            } );
        $loop->run;
    }
    $last_scan_bar->hide();
    return;
}

sub please_wait {
    $last_scan_bar->set_markup( "<span background = '#FFFFC8'>"
            . gettext('Please wait...')
            . "</span>" );
    $last_scan_bar->show_all();
    return;
}

sub get_md5 {
    my $slurp = shift;
    my $ctx   = do {
        local $/ = undef;
        open( my $F, '<', $slurp ) or do {
            show_message_dialog( $window, 'warning', 'ok',
                'Cannot open ' . $slurp . ": $!\n" );
            return;
        };
        binmode($F);
        <$F>;
    };
    return md5_hex($ctx);
}

sub about {
    my $about = Gtk2::AboutDialog->new;
    $about->set_program_name('ClamTk');
    $about->set_authors("Dave M, 2004-2012\ndave.nerd <at> gmail.com");
    $about->set_version( ClamTk::App->get_TK_version() );
    my $contributors = 'Please see http://clamtk.sf.net/credits.html';
    $about->set_translator_credits($contributors);
    $about->set_artists($contributors);
    my $logo =
          -e '/usr/share/pixmaps/clamtk.png' ? '/usr/share/pixmaps/clamtk.png'
        : 'usr/share/pixmaps/clamtk.xpm'     ? '/usr/share/pixmaps/clamtk.xpm'
        :                                      '';
    my $pixbuf = Gtk2::Gdk::Pixbuf->new_from_file($logo);
    $about->set_logo($pixbuf);
    $about->set_website('http://clamtk.sf.net');
    $about->set_comments(
        gettext(
            'ClamTk is a GUI front-end for the ClamAV antivirus using gtk2-perl.'
            ) );
    $about->set_license(
        gettext(
                  "This program is free software; you can redistribute it\n"
                . "and/or modify it under the terms of either:\n\n"
                . "a) the GNU General Public License as published by\n"
                . "the Free Software Foundation; either version 1, or\n"
                . "(at your option) any later version, or\n\n"
                . "b) the 'Artistic License'.\n\n"
                ) );
    $about->move( window_coords() );
    $about->run;
    $about->destroy;
    return;
}

1;
