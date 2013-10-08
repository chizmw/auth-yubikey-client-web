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

=head2 METHODS

=cut

=head3 nonce()

This function returns a
L<nonce|http://en.wikipedia.org/wiki/Cryptographic_nonce> for use in the
validation step,

    my $nonce = nonce();

=cut
sub nonce {
    my $data    = rand() . $$ . {} . time;
    my $key     = "@INC";
    my $digest  = hmac_sha1_hex($data, $key);
};

=head3 verify_otp($self, $otp)

Given an OTP make a call to the remote service and validate the value
provided.

This method returns an L<Auth::YubiKey::Client::Web::Response> object which
can be queried for the validity of the request.

    my $response = $self->verify_otp( $otp );
    if ($response->is_success) {
        # yay!
    }
    else {
        # boo!
    }

=cut
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

=head1 SYNOPSIS

    use Auth::YubiKey::Client::Web;

    my $yubiauth = Auth::YubiKey::Client::Web->new(
        id      => $id,
        api_key => $apikey,
    );

    my $result = $yubiauth->verify_otp($input);

    if ($result->is_success) {
        say 'Good to go';
        say 'user-id: ' . $result->public_id;
    }
    else {
        say 'Oh dear: ' . $result->status;
    }

=head1 API KEY

To use this module you will require an API key from Yubico. You can
get a key by visiting the following page and entering the required
information:

=over 4

=item L<https://upgrade.yubico.com/getapikey/>

=back

=head1 FURTHER READING

Here are some related, useful or interesting links:

=over 4

=item L<How do I get an API-Key for YubiKey development?|https://www.yubico.com/faq/api-key-yubikey-development/>

=item L<Validation Protocol Version 2.0|https://github.com/Yubico/yubikey-val/wiki/ValidationProtocolV20>

=back

=cut

1;
# ABSTRACT: Authenticate using the Yubico Web API
__END__
# vim: ts=8 sts=4 et sw=4 sr sta
