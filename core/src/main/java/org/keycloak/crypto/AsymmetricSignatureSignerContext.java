/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.crypto;

import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jwk.RSAPublicJWK;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class AsymmetricSignatureSignerContext implements SignatureSignerContext {

    private final KeyWrapper key;

    public AsymmetricSignatureSignerContext(KeyWrapper key) throws SignatureException {
        this.key = key;
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getX509CertificateSha1Thumbprint() {
        if (key.getType().equals(KeyType.RSA)) {
            JWKBuilder builder = JWKBuilder.create()
                    .kid(key.getKid())
                    .algorithm(key.getAlgorithmOrDefault());
            List<X509Certificate> certificates = Optional.ofNullable(key.getCertificateChain())
                    .filter(certs -> !certs.isEmpty())
                    .orElseGet(() -> Collections.singletonList(key.getCertificate()));
            RSAPublicJWK jwk = ((RSAPublicJWK) builder.rsa(key.getPublicKey(), certificates, key.getUse()));
            return jwk.getSha1x509Thumbprint();
        }
        return null;
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithmOrDefault();
    }

    @Override
    public String getHashAlgorithm() {
        return JavaAlgorithm.getJavaAlgorithmForHash(key.getAlgorithmOrDefault());
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            Signature signature = Signature.getInstance(JavaAlgorithm.getJavaAlgorithm(key.getAlgorithmOrDefault()));
            signature.initSign((PrivateKey) key.getPrivateKey());
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            throw new SignatureException("Signing failed", e);
        }
    }

}
