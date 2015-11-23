package Auth::YubiKey::Client::Web::Response;

use Moo;
use Digest::HMAC_SHA1 'hmac_sha1';
use MIME::Base64;

=head1 CLASS ATTRIBUTES

=cut

=head2 request_apikey

=cut
has request_apikey => (
    is          => 'ro',
    required    => 1,
);

=head2 request_otp

=cut
has request_otp => (
    is          => 'ro',
    required    => 1,
);

=head2 request_nonce

=cut
has request_nonce => (
    is          => 'ro',
    required    => 1,
);

=head2 request_response

=cut
has request_response => (
    is          => 'ro',
    required    => 1,
);

=head2 h

=cut
has h => (
    is          => 'rw'
);

=head2 t

=cut
has t => (
    is          => 'rw'
);

=head2 otp

=cut
has otp => (
    is          => 'rw'
);

=head2 nonce

=cut
has nonce => (
    is          => 'rw'
);

=head2 sl

=cut
has sl => (
    is          => 'rw'
);

=head2 status

=cut
has status => (
    is          => 'rw'
);

=head2 public_id

=cut
has public_id => (
    is          => 'rw',
);

=head2 datastring

=cut
has datastring => (
    is          => 'rw',
);

=head1 PRIVATE METHODS

=cut

=head2 BUILDARGS

=cut
sub BUILDARGS {
    my ( $class, @args ) = @_;
    unshift @args, "attr1" if @args % 2 == 1;

    # store response keys (for later verifying the response signature 'h'
    my %response_for;

    # run through the response blob; extract key=val data
    # - add key, val to @args for object initialisation
    # - store the key, val for later building and verifying the signature
    foreach my $line (split(/\n/,{@args}->{request_response})) {
        if ($line =~ /=/) {
            $line =~ s/\s//g;
            my ($key,$val) = split(/=/,$line,2);
            $response_for{$key}=$val;
            push @args, $key, $val;
        }
    }

    # store the generated response line
    push @args, 'datastring', _build_datastring(\%response_for);

    return {@args};
}

sub _build_datastring {
    my $response_for = shift;
    my @response_blobs;

    foreach my $key (sort keys %{$response_for}) {
        next if $key eq 'h'; # don't include the signature itself
        push @response_blobs,
            sprintf('%s=%s',
                $key,
                $response_for->{$key}
            )
        ;
    }
    
    return join('&', @response_blobs);
}

=head2 BUILD

=cut
sub BUILD {
    my $self = shift;

    return if $self->status eq 'NO_SUCH_CLIENT';

    if ($self->otp ne $self->request_otp) {
        $self->status('ERR_MSG_OTP');
        return;
    }

    if ($self->nonce ne $self->request_nonce) {
        $self->status('ERR_MSG_NONCE');
        return;
    }

    my $hmac = encode_base64(
        hmac_sha1(
            $self->datastring,
            decode_base64($self->request_apikey)
        )
    );
    chomp $hmac;

    if ($self->h ne $hmac) {
        $self->status('ERR_SIGNATURE_MISMATCH');
        return;
    }

    # Since the rest of the OTP is always 32 characters, the method to extract
    # the identity is to remove 32 characters from the end and then use the
    # remaining string, which should be 2-16 characters, as the YubiKey
    # identity.
    $self->public_id(
        substr $self->otp, 0, -32
    );
}

=head1 METHODS

=cut

=head2 is_success

=cut
sub is_success {
    my $self = shift;
    return !!($self->status eq 'OK');
}

=head2 is_error

=cut
sub is_error {
    my $self = shift;
    return !!($self->status ne 'OK');
}

=head2 parse_response

Nothing implemented.

=cut
sub parse_response {
    my $self = shift;
    my $response = shift;
}

1;
# ABSTRACT: Response object when using the Yubico Web API
__END__
# vim: ts=8 sts=4 et sw=4 sr sta
