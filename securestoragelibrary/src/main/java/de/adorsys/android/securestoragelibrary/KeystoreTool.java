/*
 * Copyright (C) 2019 SoryApps & adorsys GmbH & Co. KG
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.adorsys.android.securestoragelibrary;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import static de.adorsys.android.securestoragelibrary.SecureStorageException.ExceptionType.CRYPTO_EXCEPTION;
import static de.adorsys.android.securestoragelibrary.SecureStorageException.ExceptionType.INTERNAL_LIBRARY_EXCEPTION;
import static de.adorsys.android.securestoragelibrary.SecureStorageException.ExceptionType.KEYSTORE_EXCEPTION;

final class KeystoreTool {
    private static final String TAG = KeystoreTool.class.getName();

    private static final String NO_EXIST_KEYPAIR_KEYSTORE = "KeyPair does not exist in Keystore";

    private static final String KEY_ENCRYPTION_ALGORITHM = "RSA";
    private static final String KEY_CHARSET = "UTF-8";
    private static final String KEY_KEYSTORE_NAME = "AndroidKeyStore";
    private static final String KEY_CIPHER_JELLYBEAN_PROVIDER = "AndroidOpenSSL";
    private static final String KEY_CIPHER_MARSHMALLOW_PROVIDER = "AndroidKeyStoreBCWorkaround";
    private static final String KEY_TRANSFORMATION_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String KEY_X500PRINCIPAL = "CN=SecureStorage, O=SoryApps, C=Spain";

    private static final String KEY_ALIAS_PREFIX = "secst.";

    private KeyStore keystore;
    private String keyAlias;

    KeystoreTool(@NonNull String keyAlias) throws SecureStorageException
    {  init(KEY_ALIAS_PREFIX + keyAlias);  }
    private void init(@NonNull String keyAlias) throws SecureStorageException
    {
        keystore = getKeyStoreInstance();
        this.keyAlias = keyAlias;
    }

    @NonNull
    private static KeyStore getKeyStoreInstance() throws SecureStorageException {
        KeyStore keystore;

        try {
            // Get the AndroidKeyStore instance
            keystore = KeyStore.getInstance(KEY_KEYSTORE_NAME);

            // Relict of the JCA API - you have to call load even
            // if you do not have an input stream you want to load or it'll crash
            keystore.load(null);

            return keystore;
        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
    }

    boolean keyPairExists() throws SecureStorageException {
        try {
            return keystore.getKey(keyAlias, null) != null;
        } catch (NoSuchAlgorithmException e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        } catch (KeyStoreException | UnrecoverableKeyException e) {
            return false;
        }
    }

    void generateKeyPair(@NonNull Context context) throws SecureStorageException {
        // Create new key if needed
        if (!keyPairExists()) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                generateKeyPairForMarshmallow();
            } else {
                PRNGFixes.apply();
                generateKeyPairUnderMarshmallow(context);
            }
        } else if (BuildConfig.DEBUG) {
            Log.e(TAG, "KeyPair Already Exists!");
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private void generateKeyPairForMarshmallow() throws SecureStorageException {
        KeyPairGenerator generator;
        KeyGenParameterSpec keyGenParameterSpec;

        try {
            Locale.setDefault(Locale.US);

            generator = KeyPairGenerator.getInstance(KEY_ENCRYPTION_ALGORITHM, KEY_KEYSTORE_NAME);

            keyGenParameterSpec =
                    new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .setKeySize(4096)
                            .build();

            generator.initialize(keyGenParameterSpec);
            generator.generateKeyPair();
        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
    }

    private void generateKeyPairUnderMarshmallow(@NonNull Context context) throws SecureStorageException {
        Calendar start, end;
        KeyPairGeneratorSpec spec;
        KeyPairGenerator generator;

        try {
            Locale.setDefault(Locale.US);

            start = Calendar.getInstance();
            end = Calendar.getInstance();
            end.add(Calendar.YEAR, 99);

            spec = new KeyPairGeneratorSpec.Builder(context)
                    .setAlias(keyAlias)
                    .setSubject(new X500Principal(KEY_X500PRINCIPAL))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.getTime())
                    .setEndDate(end.getTime())
                    .setKeySize(4096)
                    .build();

            generator = KeyPairGenerator.getInstance(KEY_ENCRYPTION_ALGORITHM, KEY_KEYSTORE_NAME);
            generator.initialize(spec);
            generator.generateKeyPair();
        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
    }

    void deleteKeyPair() throws SecureStorageException {
        // Delete Key from Keystore
        if (keyPairExists()) {
            try {
                keystore.deleteEntry(keyAlias);
            } catch (KeyStoreException e) {
                throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
            }
        } else if (BuildConfig.DEBUG) {
            Log.e(TAG, NO_EXIST_KEYPAIR_KEYSTORE);
        }
    }

    @Nullable
    String encryptMessage(@NonNull String plainMessage) throws SecureStorageException {
        Cipher input;
        CipherOutputStream cipherOutputStream;
        byte[] values;

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                input = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM, KEY_CIPHER_MARSHMALLOW_PROVIDER);
            } else {
                input = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM, KEY_CIPHER_JELLYBEAN_PROVIDER);
            }

            input.init(Cipher.ENCRYPT_MODE, getPublicKey());

            cipherOutputStream = new CipherOutputStream(outputStream, input);
            cipherOutputStream.write(plainMessage.getBytes(KEY_CHARSET));
            cipherOutputStream.close();

            values = outputStream.toByteArray();
            return Base64.encodeToString(values, Base64.NO_WRAP);

        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
    }

    @NonNull
    String decryptMessage(@NonNull String encryptedMessage) throws SecureStorageException {
        Cipher output;
        CipherInputStream cipherInputStream;
        List<Byte> values;
        int nextByte;
        byte[] bytes;
        int i;

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                output = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM, KEY_CIPHER_MARSHMALLOW_PROVIDER);
            } else {
                output = Cipher.getInstance(KEY_TRANSFORMATION_ALGORITHM, KEY_CIPHER_JELLYBEAN_PROVIDER);
            }
            output.init(Cipher.DECRYPT_MODE, getPrivateKey());

            cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptedMessage, Base64.NO_WRAP)), output);
            values = new ArrayList<>();

            while ((nextByte = cipherInputStream.read()) != -1) { //NOPMD
                values.add((byte) nextByte);
            }

            bytes = new byte[values.size()];
            for (i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i);
            }

            return new String(bytes, 0, bytes.length, KEY_CHARSET);

        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, CRYPTO_EXCEPTION);
        }
    }

    @Nullable
    private PublicKey getPublicKey() throws SecureStorageException {
        PublicKey publicKey;
        try {
            if (keyPairExists()) {
                publicKey = keystore.getCertificate(keyAlias).getPublicKey();
            } else {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, NO_EXIST_KEYPAIR_KEYSTORE);
                }
                throw new SecureStorageException(NO_EXIST_KEYPAIR_KEYSTORE, null, INTERNAL_LIBRARY_EXCEPTION);
            }
        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
        return publicKey;
    }

    @Nullable
    private PrivateKey getPrivateKey() throws SecureStorageException {
        PrivateKey privateKey;
        try {
            if (keyPairExists()) {
                privateKey = (PrivateKey) keystore.getKey(keyAlias, null);
            } else {
                if (BuildConfig.DEBUG) {
                    Log.e(TAG, NO_EXIST_KEYPAIR_KEYSTORE);
                }
                throw new SecureStorageException(NO_EXIST_KEYPAIR_KEYSTORE, null, INTERNAL_LIBRARY_EXCEPTION);
            }
        } catch (Exception e) {
            throw new SecureStorageException(e.getMessage(), e, KEYSTORE_EXCEPTION);
        }
        return privateKey;
    }
}