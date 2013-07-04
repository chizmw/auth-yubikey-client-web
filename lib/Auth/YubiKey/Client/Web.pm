package Auth::YubiKey::Client::Web;
use Moo;

use Carp;
use Digest::HMAC_SHA1 qw(hmac_sha1_hex hmac_sha1);
use HTTP::Tiny;
use MIME::Base64;
use URI::Escape;

use Auth::YubiKey::Client::Web::Response;

has id => (
    is  => 'ro',
    isa => sub { Carp::confess( 'id must be defined' ) unless defined $_[0] },
    required => 1,
);

has api_key => (
    is  => 'ro',
    isa => sub { Carp::confess( 'api_key must be defined' ) unless defined $_[0] },
    required => 1,
);

# https://code.google.com/p/yubikey-val-server-php/wiki/GettingStartedWritingClients
has verify_url => (
    is  => 'ro',
    default => 'http://api2.yubico.com/wsapi/2.0/verify?',
);

has ua => (
    is  => 'ro',
    default => sub {
        HTTP::Tiny->new(
            agent => __PACKAGE__,
        );
    }
);

sub nonce {
    my $data    = rand() . $$ . {} . time;
    my $key     = "@INC";
    my $digest  = hmac_sha1_hex($data, $key);
};

sub verify_otp {
    my $self = shift;
    my $otp  = shift;
    
    my $nonce = nonce();
    chomp($otp);

    # Start generating the parameters
    my $params;
    $params = sprintf(
        'id=%d&nonce=%s&otp=%s&timestamp=1',
        $self->id,
        $nonce,
        uri_escape($otp)
    );
    $params .= sprintf (
        '&h=%s',
        uri_escape(
            encode_base64(hmac_sha1($params,
                    decode_base64($self->api_key)), ''))
    );
    
    my $url = $self->verify_url . $params; #join('&', @param_blobs);

    my $response = $self->ua->get( $url );

    my $yubi_response = Auth::YubiKey::Client::Web::Response->new(
        request_apikey      => $self->api_key,
        request_otp         => $otp,
        request_nonce       => $nonce,
        request_response    => $response->{content},
    );
}

1;
# ABSTRACT: Auth::YubiKey::Client::Web needs a more meaningful abstract
__END__
# vim: ts=8 sts=4 et sw=4 sr sta
