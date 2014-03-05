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
package ClamTk::Submit;
# This file probably needs some work.  Or I need to understand encoding
# better.  It's like one big hackjob.

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use LWP::UserAgent;
use Encode 'from_to', 'decode';
use Date::Calc 'Delta_Days';
use File::Basename 'basename';

use Glib 'TRUE', 'FALSE';

use Locale::gettext;
use POSIX 'locale_h', 'strftime';

# Highlights certain fields required by clamav.net's form:
my $required_field = "<span foreground = 'red'>*</span>";

# File chosen by the user for analysis:
my $chosen = '';

# Url we post to
my $url = 'http://cgi.clamav.net/';

# Main window:
my $sub_window;
my ( $name_entry,  $email_entry,  $desc_entry );
my ( $name_desc,   $email_desc );
my ( $name_string, $email_string, $file_string );
my ( $new_btn,     $close_btn,    $file_btn );
my ( $file_status, $long_string, $bottombar, $statusbar );

# This file stores the number of times the
# user has submitted a sample each day.
my ($file_path) = ClamTk::App->get_path('submit') . '/times';

sub analysis {
    # These are the main $window's x/y coordinates.
    # Seems to work intermittently, and possibly
    # less expensive than sending $window itself.
    # The ->move below shifts it to those coordinates.
    my ( undef, $x, $y ) = @_;
    $sub_window = Gtk2::Dialog->new();
    $sub_window->signal_connect( close => sub { $sub_window->destroy } );
    $sub_window->set_title( change( gettext('Submit a file for analysis') ) );
    if ( -e '/usr/share/pixmaps/clamtk.png' ) {
        $sub_window->set_default_icon_from_file(
            '/usr/share/pixmaps/clamtk.png');
    } elsif ( -e '/usr/share/pixmaps/clamtk.xpm' ) {
        $sub_window->set_default_icon_from_file(
            '/usr/share/pixmaps/clamtk.xpm');
    }
    $sub_window->move( $x, $y );

    my $vbox = Gtk2::VBox->new( FALSE, 1 );
    $sub_window->get_content_area()->add($vbox);

    my $prelude = create_view();
    $vbox->pack_start( $prelude, TRUE, TRUE, 1 );

    my $table = Gtk2::Table->new( 3, 7, FALSE );
    $vbox->pack_start( $table, FALSE, FALSE, 0 );
    $table->set_row_spacings(5);
    $table->set_border_width(2);

    $name_desc = Gtk2::Label->new;
    $table->attach_defaults( $name_desc, 0, 1, 0, 1 );
    $name_string = change( gettext('Name') );
    $name_desc->set_markup($name_string);
    my $n_filled_field = Gtk2::Label->new;
    $n_filled_field->set_markup($required_field);
    $table->attach_defaults( $n_filled_field, 1, 2, 0, 1 );
    $name_entry = Gtk2::Entry->new_with_max_length(40);
    $table->attach_defaults( $name_entry, 2, 3, 0, 1 );
    $name_entry->signal_connect(
        'insert-text' => sub {
            my ( $widget, $string, $position ) = @_;
            if ( $string !~ m#[\w0-9\.\-\_\s]# ) {
                $name_entry->signal_stop_emission_by_name('insert-text');
            }
            return;
        } );

    $email_desc = Gtk2::Label->new;
    $table->attach_defaults( $email_desc, 0, 1, 1, 2 );
    $email_string = change( gettext('Email') );
    $email_desc->set_markup($email_string);
    my $e_filled_field = Gtk2::Label->new;
    $e_filled_field->set_markup($required_field);
    $table->attach_defaults( $e_filled_field, 1, 2, 1, 2 );
    $email_entry = Gtk2::Entry->new_with_max_length(80);
    $table->attach_defaults( $email_entry, 2, 3, 1, 2 );
    $email_entry->signal_connect(
        'insert-text' => sub {
            my ( $widget, $string, $position ) = @_;

            if ( $string !~ m#[\w0-9\.\@\-\_]# ) {
                $email_entry->signal_stop_emission_by_name('insert-text');
            }
            return;
        } );

    # The default string for the area holding the filename
    $file_string = change( gettext('No file selected') );
    # This shades it a little
    $long_string = "<span foreground='#CCCCCC'>$file_string</span>";

    my $file_text = change( gettext('Select File') );
    $file_btn = Gtk2::Button->new($file_text);
    $table->attach_defaults( $file_btn, 0, 1, 2, 3 );
    $file_btn->signal_connect(
        clicked => sub {
            $chosen = select_file();
            if ( $chosen && -e $chosen && -s $chosen ) {
                # The following are things I've seen in filenames
                # for malware: [a-z], [0-9], spaces, literal dots,
                # parens, hyphens, pound (# - seen in UPS crapware),
                # literal question marks, equals (exploit kit stuff)
                if ( $chosen =~ m!^([#\w\s/\.\(\)\?\-=]+)$! ) {
                    $file_status->set_text( basename($1) );
                } else {
                    $file_status->set_markup(
                        qq(<span underline="error" underline_color="red">$file_string</span>)
                        );
                    field_loop();
                    $file_status->set_markup($long_string);
                    $file_btn->grab_focus();
                }
            }
        } );
    my $f_filled_field = Gtk2::Label->new;
    $f_filled_field->set_markup($required_field);
    $table->attach_defaults( $f_filled_field, 1, 2, 2, 3 );
    $file_status = Gtk2::Label->new();
    $table->attach_defaults( $file_status, 2, 3, 2, 3 );
    $file_status->set_markup($long_string);
    $file_status->set_ellipsize('middle');

    # The file can be categorized as either
    # new malware (undetected) or a false positive.
    # New malware is the default option.
    my $sampleis_text =
        Gtk2::Label->new( change( gettext('The attached file is') ) );
    $table->attach_defaults( $sampleis_text, 0, 1, 3, 4 );
    my $bb = Gtk2::HButtonBox->new();
    $bb->set_layout('end');
    $table->attach_defaults( $bb, 1, 3, 3, 4 );
    $new_btn =
        Gtk2::RadioButton->new( undef, change( gettext('New malware') ) );
    my $false_pos =
        Gtk2::RadioButton->new( $new_btn,
        change( gettext('A false positive') ) );
    $bb->add($new_btn);
    $bb->add($false_pos);

    # Optional description of the file being uploaded
    my $desc_text  = change( gettext('Description') );
    my $desc_label = Gtk2::Label->new($desc_text);
    $table->attach_defaults( $desc_label, 0, 1, 4, 5 );
    $desc_entry = Gtk2::Entry->new_with_max_length(50);
    $table->attach_defaults( $desc_entry, 1, 3, 4, 5 );
    $desc_entry->signal_connect(
        'insert-text' => sub {
            my ( $widget, $string, $position ) = @_;

            if ( $string !~ m#[\w0-9\.\@\-\s]# ) {
                $desc_entry->signal_stop_emission_by_name('insert-text');
            }
            return;
        } );

    $statusbar = Gtk2::Label->new();
    $table->attach_defaults( $statusbar, 0, 3, 5, 6 );

    $bottombar = Gtk2::Toolbar->new();
    $table->attach_defaults( $bottombar, 0, 3, 6, 7 );
    $bottombar->set_style('both-horiz');

    my $ssep = Gtk2::SeparatorToolItem->new;
    $ssep->set_draw(FALSE);
    $ssep->set_expand(TRUE);
    $bottombar->insert( $ssep, -1 );

    my $clear_btn = Gtk2::ToolButton->new_from_stock('gtk-clear');
    $clear_btn->set_is_important(TRUE);
    $bottombar->insert( $clear_btn, -1 );
    $clear_btn->signal_connect( clicked => \&clear );
    $clear_btn->grab_focus();

    $bottombar->insert( Gtk2::SeparatorToolItem->new, -1 );

    my $quit_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $quit_btn->set_is_important(TRUE);
    $bottombar->insert( $quit_btn, -1 );
    $quit_btn->signal_connect( clicked => sub { $sub_window->destroy } );

    $bottombar->insert( Gtk2::SeparatorToolItem->new, -1 );

    my $forward_btn = Gtk2::ToolButton->new_from_stock('gtk-go-forward');
    $forward_btn->set_is_important(TRUE);
    $bottombar->insert( $forward_btn, -1 );
    $forward_btn->signal_connect( clicked => \&double_check );

    $close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $close_btn->set_is_important(TRUE);
    $vbox->pack_start( $close_btn, FALSE, FALSE, 5 );
    $close_btn->signal_connect( clicked => sub { $sub_window->destroy } );

    $sub_window->show_all();
    $close_btn->hide();
    $name_entry->grab_focus;

    # Check if user has already submitted two for the day;
    # if so, give popup window and return
    my $amount = get_amount();
    if ( $amount >= 2 ) {
        my $message =
            change(
            gettext('Please do not submit more than two files per day.') );
        my $dialog =
            Gtk2::MessageDialog->new_with_markup( $sub_window,
            [qw(modal destroy-with-parent)],
            'info', 'ok', $message );
        $dialog->run;
        $sub_window->destroy();
    }
}

sub clear {
    $name_entry->set_text('');
    $email_entry->set_text('');
    $file_status->set_markup($long_string);
    $desc_entry->set_text('');
    $name_entry->grab_focus();
    return;
}

sub select_file {
    my $picker = Gtk2::FileChooserDialog->new(
        change( gettext('Select File') ), $sub_window, 'open',
        'gtk-cancel' => 'cancel',
        'gtk-ok'     => 'ok',
        );
    if ( 'ok' eq $picker->run() ) {
        my $gotone = $picker->get_filename();
        $picker->destroy;
        return $gotone;
    } else {
        $picker->destroy;
        return;
    }
}

sub double_check {
    unless ( length( $name_entry->get_text )
        && length( $email_entry->get_text )
        && ( $chosen && -e $chosen )
        && valid_email( $email_entry->get_text ) ) {
        field_check() || return;
    }

    my $message =
        change( gettext('You are about to submit a file for analysis.') );
    $message .= "\n\n";
    $message
        .= change( gettext('Press OK to continue, or Cancel to go back.') );

    my $dialog =
        Gtk2::MessageDialog->new( $sub_window, 'destroy-with-parent', 'info',
        'ok-cancel', $message );
    if ( 'ok' eq $dialog->run() ) {
        $dialog->destroy();
        submit();
    } else {
        $dialog->destroy();
    }
    return;
}

sub submit {
    # Don't need buttons to click anymore.
    # If we manipulate the buttons this way, we can
    # avoid them having to be global variables.
    my @bchild = $bottombar->get_children;
    for my $l (@bchild) {
        if ( $l->isa('Gtk2::Button') ) {
            $l->set_sensitive(FALSE);
        }
    }

    # Our $ua
    my $ua = LWP::UserAgent->new;

    # Custom useragent by request
    $ua->agent('ClamTk/Automatic_Submission');
    $ua->timeout(60);

    # Submit these variables, plus $chosen (the file)
    my $sendername  = $name_entry->get_text;
    my $email       = $email_entry->get_text;
    my $description = $desc_entry->get_text || '';
    my $sampleis    = ( $new_btn->get_active ) ? 'virus' : 'falsepositive';

    # URL we're posting to
    $url .= ( $sampleis eq 'virus' ) ? 'sendmalware.cgi' : 'sendfp.cgi';

    # Apparently this is necessary
    from_to( $sendername,  'ISO-8859-1', 'UTF-8' );
    from_to( $email,       'ISO-8859-1', 'UTF-8' );
    from_to( $description, 'ISO-8859-1', 'UTF-8' );
    from_to( $sampleis,    'ISO-8859-1', 'UTF-8' );
    from_to( $chosen,      'ISO-8859-1', 'UTF-8' );

    $statusbar->set_text( change( gettext('Please wait...') ) );
    Gtk2->main_iteration while ( Gtk2->events_pending );

    my $req = $ua->post(
        $url,
        Content_Type => 'form-data',
        Content      => [
            action       => 'submit',
            sendername   => $sendername,
            email        => $email,
            'Send virus' => 'submit',
            name         => $description,
            sampleis     => $sampleis,
            file         => [$chosen],
            ],
            );

    if (   $req->is_success
        && $req->decoded_content =~ /has been successfully sent/ ) {
        increase_amount();
        finish('success');
    } elsif ( $req->decoded_content =~ /already recognized/ ) {
        my $as = '';
        if ( $req->decoded_content =~ /as (.*?) . Be/ ) {
            $as = $1;
        }
        increase_amount();
        finish( 'known', $as );
    } else {
        finish('failed');
    }
}

sub finish {
    my $status = shift;
    my $known  = shift;

    $bottombar->hide();

    my $message = "\n";
    if ( $status eq 'success' ) {
        $message = change( gettext('The submission was successful!') );
    } elsif ( $status eq 'known' ) {
        $message =
            change( gettext('The file you submitted is already recognized') );
        $message .= "\n";
        if ($known) {
            $message .= "($known)";
        } else {
            $message .= '.';
        }
    } else {
        $message = change(
            gettext(
                'Unable to complete the submission. Please try again later.')
                );
    }
    $statusbar->set_text($message);
    clear();
    $close_btn->show();
}

sub create_view {
    my $view = Gtk2::TextView->new;
    $view->set_wrap_mode('word');
    $view->set_editable(FALSE);
    $view->set_cursor_visible(FALSE);
    $view->set_indent(5);

    my $sw = Gtk2::ScrolledWindow->new;
    $sw->set_shadow_type('etched-in');
    $sw->set_policy( 'never', 'never' );
    $sw->set_border_width(5);

    my @text = (
        change( gettext('With this form, you can:') ),
        change( gettext('Report new viruses which are not detected') ),
        change(
            gettext('Report clean files which are incorrectly detected')
            ),
        change(
            gettext('Please do not submit more than two files per day.')
            ),
            );

    my $line = "\n";
    $line .= $text[0];
    $line .= "\n\n";
    $line .= "* ";
    $line .= $text[1];
    $line .= "\n";
    $line .= "* ";
    $line .= $text[2];
    $line .= "\n\n";
    $line .= $text[3];
    $line .= "\n\n";

    my $buffer = $view->get_buffer;
    my $iter   = $buffer->get_iter_at_offset(0);
    $buffer->create_tag( 'mono', family     => 'Monospace' );
    $buffer->create_tag( 'red',  foreground => 'red' );
    $buffer->insert_with_tags_by_name( $iter, $line, 'mono' );
    $buffer->insert_with_tags_by_name( $iter, '* ',  'red' );
    $buffer->insert_with_tags_by_name( $iter,
        change( gettext('Indicates a required field') ), 'mono' );

    $sw->add($view);
    return $sw;
}

sub field_check {
    # This subroutine sanity-checks all the fields to ensure
    # they're filled out properly.  Some of the fields are mandatory,
    # such as Name, Email and, of course, there must be a file.
    # The Description field check only removes leading and ending
    # white spaces (for now).
    # I'll likely take some heat for the 'mandatory' fields, but
    # those are ClamAV's rules, not mine. :)  I'm sure they
    # have their reasons.

    # check name_entry
    my $tmp = $name_entry->get_text();
    $tmp =~ s/^\s+//;
    $tmp =~ s/\s+$//;
    if ( !length( $name_entry->get_text() ) || !length($tmp) ) {
        $name_desc->set_markup(
            qq(<span underline="error" underline_color="red">$name_string</span>)
            );
        field_loop();
        $name_desc->set_markup($name_string);
        $name_entry->grab_focus();
        return 0;
    }

    # check email_entry
    $tmp = $email_entry->get_text();
    $tmp =~ s/^\s+//;
    $tmp =~ s/\s+$//;
    if ( !length( $email_entry->get_text() ) || !length($tmp) ) {
        $email_desc->set_markup(
            qq(<span underline="error" underline_color="red">$email_string</span>)
            );
        field_loop();
        $email_desc->set_markup($email_string);
        $email_entry->grab_focus();
        return 0;
    }

    # check file field
    if ( !-e $chosen ) {
        $file_status->set_markup(
            qq(<span underline="error" underline_color="red">$file_string</span>)
            );
        field_loop();
        $file_status->set_markup($long_string);
        $file_btn->grab_focus();
        return 0;
    }

    # check desc field
    $tmp = $desc_entry->get_text();
    $tmp =~ s/^\s+//;
    $tmp =~ s/\s+$//;
    $desc_entry->set_text($tmp);

    return;
}

sub field_loop {
    # This is a sexy non-blocking subroutine.
    # It actually only allows *something* to happen for a few seconds.
    my $loop = Glib::MainLoop->new;
    Glib::Timeout->add(
        1000,
        sub {
            $loop->quit;
            FALSE;
        } );
    $loop->run;
    return;
}

sub test_date {
    my ( $year1, $month1, $day1 ) = get_todays_date();
    my ( $year2, $month2, $day2 ) = get_file_date();
    #warn "year1 = >$year1<, month1 =>$month1<, day1 = >$day1<\n";
    #warn "year2 = >$year2<, month2 =>$month2<, day2 = >$day2<\n";
    my $diff = Delta_Days( $year1, $month1, $day1, $year2, $month2, $day2 );

    # The date in the file needs to be changed to today.
    # This will blow away the old one and create a new one
    if ($diff) {
        create_file();
    }
    return;
}

sub create_file {
    open( my $f, '>:encoding(UTF-8)', $file_path )
        or do {
        warn "Could not open $file_path to create_file: $!\n";
        return;
        };
    my $today = join( ':', get_todays_date() );
    print $f "$today:0";
    close($f);
    return;
}

sub get_amount {
    open( my $f, '<:encoding(UTF-8)', $file_path )
        or do {
        warn "Could not open $file_path for reading to get_amount: $!\n";
        return 3;
        };
    my $amount;
    while (<$f>) {
        chomp;
        # example: 2010:10:02:0
        ( undef, undef, undef, $amount ) = split /:/;
    }
    close($f);
    return $amount;
}

sub get_file_date {
    my ( $year, $month, $day );
    open( my $f, '<:encoding(UTF-8)', $file_path )
        or do {
        # We don't want to just die because we can't read the date
        # from the file.  So we'll just assume it's today instead.
        warn "Could not open $file_path for reading to get_file_date: $!\n";
        ( $year, $month, $day, undef ) = split /:/;
        return ( $year, $month, $day );
        };
    while (<$f>) {
        chomp;
        ( $year, $month, $day, undef ) = split /:/;
    }
    close($f);
    return ( $year, $month, $day );
}

sub increase_amount {
    my $current = get_amount();
    $current++;
    my $today = join( ':', get_todays_date() );

    open( my $f, '>:encoding(UTF-8)', $file_path )
        or do {
        warn "Could not open $file_path for writing to increase_amount: $!\n";
        return;
        };
    print $f "$today:$current";
    close($f);
    return;
}

sub get_todays_date {
    my ( $day, $month, $year ) = split / /, strftime( '%d %m %Y', localtime );
    return ( $year, $month, $day );
}

sub change {
    return decode( 'utf-8', $_[0] );
}

sub valid_email {
    my $check = shift;
#<<< Perltidy needs to ignore this.
    # email $reg is by jfriedl, Mastering Regular Expressions.
    my $reg =
'(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n
\015()]|\\[^\x80-\xff])*\))*\))*(?:(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\
xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|"(?:[^\\\x80-\xff\n\015"
]|\\[^\x80-\xff])*")(?:(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xf
f]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*\.(?:[\040\t]|\((?:[
^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\
xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;
:".\\\[\]\000-\037\x80-\xff])|"(?:[^\\\x80-\xff\n\015"]|\\[^\x80-\xff])*"))
*(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\
n\015()]|\\[^\x80-\xff])*\))*\))*@(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\
\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\04
0)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-
\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\])(?:(?:[\040\t]|\((?
:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80
-\xff])*\))*\))*\.(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\(
(?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]
\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\
\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\]))*|(?:[^(\040)<>@,;:".\\\[\]\000-\0
37\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|"(?:[^\\\x80-\xf
f\n\015"]|\\[^\x80-\xff])*")(?:[^()<>@,;:".\\\[\]\x80-\xff\000-\010\012-\03
7]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\
\[^\x80-\xff])*\))*\)|"(?:[^\\\x80-\xff\n\015"]|\\[^\x80-\xff])*")*<(?:[\04
0\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]
|\\[^\x80-\xff])*\))*\))*(?:@(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x
80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@
,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]
)|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\])(?:(?:[\040\t]|\((?:[^\\
\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff
])*\))*\))*\.(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^
\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]\000-
\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-
\xff\n\015\[\]]|\\[^\x80-\xff])*\]))*(?:(?:[\040\t]|\((?:[^\\\x80-\xff\n\01
5()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*,(?
:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\0
15()]|\\[^\x80-\xff])*\))*\))*@(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^
\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<
>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xf
f])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff])*\])(?:(?:[\040\t]|\((?:[^
\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\x
ff])*\))*\))*\.(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:
[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]\00
0-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x8
0-\xff\n\015\[\]]|\\[^\x80-\xff])*\]))*)*:(?:[\040\t]|\((?:[^\\\x80-\xff\n\
015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*)
?(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000
-\037\x80-\xff])|"(?:[^\\\x80-\xff\n\015"]|\\[^\x80-\xff])*")(?:(?:[\040\t]
|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[
^\x80-\xff])*\))*\))*\.(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xf
f]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@,;:".\
\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|"(?:
[^\\\x80-\xff\n\015"]|\\[^\x80-\xff])*"))*(?:[\040\t]|\((?:[^\\\x80-\xff\n\
015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*@
(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n
\015()]|\\[^\x80-\xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff
]+(?![^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\
]]|\\[^\x80-\xff])*\])(?:(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\
xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*\.(?:[\040\t]|\((?
:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80
-\xff])*\))*\))*(?:[^(\040)<>@,;:".\\\[\]\000-\037\x80-\xff]+(?![^(\040)<>@
,;:".\\\[\]\000-\037\x80-\xff])|\[(?:[^\\\x80-\xff\n\015\[\]]|\\[^\x80-\xff
])*\]))*(?:[\040\t]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff]|\((?:[^\\\x8
0-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*>)(?:[\040\t]|\((?:[^\\\x80-\xff\n\
015()]|\\[^\x80-\xff]|\((?:[^\\\x80-\xff\n\015()]|\\[^\x80-\xff])*\))*\))*';
#>>>

    $reg =~ s/\n//g;
    if ( $check =~ /$reg/o ) {
        return 1;
    } else {
        $email_desc->set_markup(
            qq(<span underline="error" underline_color="red">$email_string</span>)
            );
        field_loop();
        $email_desc->set_markup($email_string);
        $email_entry->grab_focus();
        return 0;
    }
}

1;
