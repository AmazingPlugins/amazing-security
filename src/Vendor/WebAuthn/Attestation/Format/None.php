<?php
// phpcs:ignoreFile -- Pinned third-party verifier; integrity checked by scripts/passkey-vendor-manifest.php.


namespace AmazingPlugins\Security\Vendor\WebAuthn\Attestation\Format;

defined( 'ABSPATH' ) || exit;
use AmazingPlugins\Security\Vendor\WebAuthn\Attestation\AuthenticatorData;
use AmazingPlugins\Security\Vendor\WebAuthn\WebAuthnException;

class None extends FormatBase {


    public function __construct($AttestionObject, AuthenticatorData $authenticatorData) {
        parent::__construct($AttestionObject, $authenticatorData);
    }


    /*
     * returns the key certificate in PEM format
     * @return string
     */
    public function getCertificatePem() {
        return null;
    }

    /**
     * @param string $clientDataHash
     */
    public function validateAttestation($clientDataHash) {
        return true;
    }

    /**
     * validates the certificate against root certificates.
     * Format 'none' does not contain any ca, so always false.
     * @param array $rootCas
     * @return boolean
     * @throws WebAuthnException
     */
    public function validateRootCertificate($rootCas) {
        return false;
    }
}
