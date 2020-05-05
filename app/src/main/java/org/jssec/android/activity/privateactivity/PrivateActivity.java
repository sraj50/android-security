/*
 * Copyright (C) 2012-2019 Japan Smartphone Security Association
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

package org.jssec.android.activity.privateactivity;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.Toast;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Arrays;

import org.jssec.android.activity.privateactivity.PrivateUserActivity.keystore_info;
//Appropriate libraries need to be also imported

public class PrivateActivity extends Activity {
    private KeyStore my_ks;

    @TargetApi(Build.VERSION_CODES.O)
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.private_activity);

        // Handle the received Intent carefully and securely,
        // even though the Intent was sent from the same application.

        Intent intent = this.getIntent();
        PrivateUserActivity.keystore_info param = (PrivateUserActivity.keystore_info) intent.getSerializableExtra("CL_k");


        //CODE MUST BE ADDED HERE IN ORDER TO HANDLE the COLLECTED OBJECT from the Intent
        keystore_info ksInfo = (keystore_info) getIntent().getSerializableExtra("CL_k");
//        Toast.makeText(this, ksInfo.getPassword_val(), Toast.LENGTH_SHORT).show();

        try {
            if (ksInfo.getKeystore_file().equals("default")) {
                // default Android keystore

                // generate key pair with self-signed certificate, purpose is to only sign without user authentication
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                KeyGenParameterSpec kgps = new KeyGenParameterSpec.Builder(
                        "key1",
                        KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        //
                        .setUserAuthenticationRequired(false)
                        .build();
                kpg.initialize(kgps);
                KeyPair kp = kpg.generateKeyPair();

                // obtain key from Android keystore
                KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
                PrivateKey privateKey = (PrivateKey) ks.getKey("key1", null);
                PublicKey publicKey = ks.getCertificate("key1").getPublicKey();
//
//                KeyStore.Entry keyEntry = ks.getEntry("key1", null);
//                keyEntry.getAttributes();

                Toast.makeText(this, kpg.getAlgorithm(), Toast.LENGTH_SHORT).show();
//                Toast.makeText(this, kgps.getCertificateSerialNumber().toString(), Toast.LENGTH_SHORT).show();
//                Toast.makeText(this, ks.getCertificate("key1").getType(), Toast.LENGTH_SHORT).show();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }

    }

    public void onReturnResultClick(View view) {

        // Sensitive information can be sent since it is sending
        // and receiving all within the same application.
        Intent intent = new Intent();

        //CORE MUST BE ADDED HERE IN ORDER TO send the appropriate values to the PrivateUserActivity
        //i.e. the "Sensitive Info" value should be changed with something different

        intent.putExtra("RESULT", "Sensitive Info");

        setResult(RESULT_OK, intent);
        finish();
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();

        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xFF & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
