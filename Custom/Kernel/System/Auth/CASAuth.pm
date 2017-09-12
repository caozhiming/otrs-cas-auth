package Kernel::System::Auth::CASAuth;

use strict;
use AuthCAS;

use vars qw($VERSION %Env);

sub new {
    my $Type  = shift;
    my %Param = @_;

    # allocate new hash for object
    my $Self = {};
    bless( $Self, $Type );

    # check needed objects
    #foreach (qw(LogObject ConfigObject DBObject)) {
    #    $Self->{$_} = $Param{$_} || die "No $_!";
    #}

    # get config object
    my $ConfigObject = $Kernel::OM->Get('Kernel::Config');

    # Debug 0=off 1=on
    $Self->{Debug} = 1;

    # Check of er een CASurl is
    $Self->{CASurl} = $ConfigObject->Get('AuthModule::CASAuth::CASurl')
      || die
      "casAUTH requires AuthModule::casAuth::CASurl in Kernel/Config.pm!";

    # Check of er een CAfile is
    $Self->{CAfile} = $ConfigObject->Get('AuthModule::CASAuth::CAfile')
      || undef;

    # Maak het CAS object aan
    my $CASobject;
    if ( defined $Self->{CAfile} ) {
        $CASobject = new AuthCAS(
            'casUrl' => $Self->{CASurl},
            'CAFile' => $Self->{CAfile},
        );
    }
    else {
        $CASobject = new AuthCAS( 'casUrl' => $Self->{CASurl}, );
    }
    $Self->{CASobject} = $CASobject;

    # pas de login url aan zodat cas zijn werk kan doen
    $ConfigObject->{LoginURL} = '/' . $ConfigObject->{'ScriptAlias'} . 'index.pl?Action=Login&';

    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'error',
        Message  => $ConfigObject->{LoginURL}
    );

    # ThisURL , the URL cas posts back to.
    $Self->{ThisURL} =
      $ConfigObject->{'HttpType'} . "://" .  # Support for http/https
      $ConfigObject->{'FQDN'}  .              # FQDN; otrsdev1.ugent.be
      $ConfigObject->{LoginURL};             # login URL
    $Kernel::OM->Get('Kernel::System::Log')->Log(
        Priority => 'error',
        Message  => $Self->{ThisURL}
    );
    return $Self;
}

sub GetOption {
    my $Self  = shift;
    my %Param = @_;

    # check needed stuff
    if ( !$Param{What} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => 'Need What!'
        );
        return;
    }

    # module options
    my %Option = ( PreAuth => 0, );

    # return option
    return $Option{ $Param{What} };
}

sub Auth {
    my $Self  = shift;
    $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => 'Debug: Auth started') if ( $Self->{Debug} );
    my %Param = @_;

    # if debug; zeg auth gestart en print %Param
    if ( $Self->{Debug} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => "Debug %Param: ". %Param);

        my $ParamList;
        foreach $a (%Param) {
          $ParamList .= "'". $a . "' ";
        }
        $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => "Debug %Param: ". $ParamList);
    }

    # Deze site url
    my $ThisURL = $Self->{ThisURL};

    # authCAS object
    my $CASobject = $Self->{CASobject};
    # CGI object
    my $CGI = new CGI;
    # if debug; print CGI param
    if ( $Self->{Debug} ) {
        $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => "Debug: CGI: ". $CGI->param);
        foreach $a ($CGI->param) {
            $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => "Debug: CGI ".$a.": ". $CGI->param($a));
        }
    }

    # Als OTRS een reason terug geeft, stop en meld aan de gebruiker
    my $Reason = $CGI->param('Reason') . $CGI->param('?Reason');
    if ( $Reason ) {
        my $ReasonError = "CAS auth: OTRS authentication error: " . $Reason;
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => $ReasonError
        );
        die $ReasonError unless ( $Reason =~ /InvalidSessionID/ ) ;
    }

    # Haal de ticket uit de parameters
    my $GivenServiceTicket = $CGI->param('ticket');

    # Check of er een Service Ticket is
    if ( defined $GivenServiceTicket ) {

        $ThisURL = $Self->{ThisURL};
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => $ThisURL.'---'.$GivenServiceTicket
        );

        # Valideer het ST
        my $UserID = $CASobject->validateST( $ThisURL, $GivenServiceTicket );
        # if debug; CASobject returned $UserID
        $Kernel::OM->Get('Kernel::System::Log')->Log(Priority => 'error',Message  => "Debug: CASobject UserID: ". $UserID ) if ( $Self->{Debug} );
        # Als de ST een user opleverde is de gebruiker ingelogged
        if ( defined $UserID ) {
            $Self->{LogoutURL} = $CASobject->getServerLogoutURL($ThisURL);
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => "CAS auth: $UserID authentication ok."
            );
            return $UserID;

            # Anders is de authenticatie gefaald
        }
        else {
            my $error = "CAS auth: authentication failed: " . &AuthCAS::get_errors();
            $Kernel::OM->Get('Kernel::System::Log')->Log(
                Priority => 'error',
                Message  => $error
            );
            return;
        }

    }

    # Als er geen ST is moet er een gehaald worden via onderstaande URL
    else {
        my $url = $CASobject->getServerLoginURL( $Self->{ThisURL} );
        my $error = "CAS auth: No CAS ticket. Probably a new login; redirecting to CAS at $url";
        $Kernel::OM->Get('Kernel::System::Log')->Log(
            Priority => 'error',
            Message  => $error
        );
        print "Location: $url\n\n";
    }

    return;
}

1;    # Because perl likes a Happy Ending
