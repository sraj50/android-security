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

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import android.os.Environment;
import android.os.storage.StorageVolume;
import android.provider.MediaStore;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import org.jssec.android.activity.privateactivity.PrivateUserActivity.keystore_info;
//Appropriate libraries need to be also imported

public class PrivateActivity extends Activity {
    private static String msgToSign;
    private static String aliasUser;
    private static String sigStr;
    private EditText msg;
    private EditText aliasEntry;

    private keystore_info ksInfo;
    private KeyStore ksAndroid;
    private KeyStore ksCustom;

    private static final int REQUEST_READ_PERMISSION = 111;


    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.private_activity);

        // Handle the received Intent carefully and securely,
        // even though the Intent was sent from the same application.

        Intent intent = this.getIntent();
        PrivateUserActivity.keystore_info param = (PrivateUserActivity.keystore_info) intent.getSerializableExtra("CL_k");


        //CODE MUST BE ADDED HERE IN ORDER TO HANDLE the COLLECTED OBJECT from the Intent
        ksInfo = (keystore_info) getIntent().getSerializableExtra("CL_k");

        try {
            // default Android keystore
            if (ksInfo.getKeystore_file().equals("default")) {

                // obtain key from Android keystore
                ksAndroid = KeyStore.getInstance("AndroidKeyStore");
                ksAndroid.load(null);

                KeyPairGenerator kpg = null;
                KeyGenParameterSpec kgps = null;
                KeyPair kp = null;

                // generate key pair with self-signed certificate, purpose is to only sign without user authentication
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ksAndroid.getProvider());
                kgps = new KeyGenParameterSpec.Builder(
                        "key1",
                        KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setUserAuthenticationRequired(false)
                        .build();
                kpg.initialize(kgps);
                kp = kpg.generateKeyPair();


                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ksAndroid.getProvider());
                kgps = new KeyGenParameterSpec.Builder(
                        "key2",
                        KeyProperties.PURPOSE_SIGN)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setUserAuthenticationRequired(false)
                        .build();
                kpg.initialize(kgps);
                kp = kpg.generateKeyPair();

                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ksAndroid.getProvider());
                kgps = new KeyGenParameterSpec.Builder(
                        "key3",
                        KeyProperties.PURPOSE_SIGN)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setUserAuthenticationRequired(false)
                        .build();
                kpg.initialize(kgps);
                kp = kpg.generateKeyPair();

                // display key alias, certificate type and key algorithm
                TextView aliasView = (TextView) findViewById(R.id.alias_text);
                Enumeration<String> e =  ksAndroid.aliases();

                while (e.hasMoreElements()) {
                    String alias = e.nextElement();
                    KeyStore.PrivateKeyEntry privateKeyEntry =  (KeyStore.PrivateKeyEntry) ksAndroid.getEntry(alias, null);
                    aliasView.append("Alias: " + alias + " Cert type: " + privateKeyEntry.getCertificate().getType() + " Key type: " + privateKeyEntry.getPrivateKey().getAlgorithm());
                    aliasView.append("\n");
                }

                // get key alias from user
                aliasEntry = (EditText) findViewById(R.id.editText2);
                aliasEntry.addTextChangedListener(new EditTextWatcher(this, aliasEntry));

                // get message from user to digitally sign
                msg = (EditText) findViewById(R.id.alias_entr);
                msg.addTextChangedListener(new EditTextWatcher(this, msg));



            } else {
                // custom keystore
                if (!ksInfo.getPassword_val().equals("password")) {

                    // handle incorrect password
                    Toast.makeText(this, "Incorrect password, unable to open keystore", Toast.LENGTH_SHORT).show();
                } else {
                    // correct password
                    ksCustom = KeyStore.getInstance("pkcs12");

                    // if no permission to read from storage
                    if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
//                    Toast.makeText(this, "No permission to read storage", Toast.LENGTH_SHORT).show();

                        // request permission from user
                        ActivityCompat.requestPermissions(this, new String[] {Manifest.permission.READ_EXTERNAL_STORAGE}, REQUEST_READ_PERMISSION);
                    } else {
                        // permission granted
//                    Toast.makeText(this, "Permission granted to read storage", Toast.LENGTH_SHORT).show();
                        // perform task
                        if (Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED)) {
                            try (InputStream ksData = new FileInputStream("/sdcard/Download" + File.separator + ksInfo.getKeystore_file())) {
                                ksCustom.load(ksData, ksInfo.getPassword_val().toCharArray());
                            }
                        }
                    }

                    // display key alias, certificate type and key algorithm
                    TextView aliasView = (TextView) findViewById(R.id.alias_text);
                    Enumeration<String> e =  ksCustom.aliases();

                    while (e.hasMoreElements()) {
                        String alias = e.nextElement();
                        KeyStore.PrivateKeyEntry privateKeyEntry =  (KeyStore.PrivateKeyEntry) ksCustom.getEntry(alias, null);
                        aliasView.append("Alias: " + alias + " Cert type: " + privateKeyEntry.getCertificate().getType() + " Key type: " + privateKeyEntry.getPrivateKey().getAlgorithm());
                        aliasView.append("\n");
                    }

                    // get key alias from user
                    aliasEntry = (EditText) findViewById(R.id.editText2);
                    aliasEntry.addTextChangedListener(new EditTextWatcher(this, aliasEntry));

                    // get message from user to digitally sign
                    msg = (EditText) findViewById(R.id.alias_entr);
                    msg.addTextChangedListener(new EditTextWatcher(this, msg));
                }
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void onReturnResultClick(View view) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException, UnrecoverableEntryException {

        // Sensitive information can be sent since it is sending
        // and receiving all within the same application.
        Intent intent = new Intent();

        //CORE MUST BE ADDED HERE IN ORDER TO send the appropriate values to the PrivateUserActivity
        //i.e. the "Sensitive Info" value should be changed with something different

        // sign data using key
        if (aliasUser != null) {
            if (msgToSign != null) {
                if (ksInfo.getKeystore_file().equals("default")) {
                    // default Android keystore
                    if (aliasUser.equals("key1")) {
                        // for key of algorithm EC
                        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ksAndroid.getEntry(aliasUser, null);
                        byte[] data = msgToSign.getBytes(StandardCharsets.UTF_8);
                        Signature sig = Signature.getInstance("SHA256withECDSA");
                        sig.initSign(pkEntry.getPrivateKey());
                        sig.update(data);
                        byte[] sigBytes = sig.sign();
                        if (sigBytes.length > 0) {
                            sigStr = toHexString(sigBytes);
                        }
                    } else if (aliasUser.equals("key2") || aliasUser.equals("key3")) {
                        // for key of algorithm RSA
                        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ksAndroid.getEntry(aliasUser, null);
                        byte[] data = msgToSign.getBytes(StandardCharsets.UTF_8);
                        Signature sig = Signature.getInstance("SHA256withRSA");
                        sig.initSign(pkEntry.getPrivateKey());
                        sig.update(data);
                        byte[] sigBytes = sig.sign();
                        if (sigBytes.length > 0) {
                            sigStr = toHexString(sigBytes);
                        }
                    }
                } else {
                    // custom keystore
                    if (aliasUser.equals("key4")) {
                        // for key of algorithm RSA
                        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ksCustom.getEntry(aliasUser, null);
                        byte[] data = msgToSign.getBytes(StandardCharsets.UTF_8);
                        Signature sig = Signature.getInstance("SHA256withRSA");
                        sig.initSign(pkEntry.getPrivateKey());
                        sig.update(data);
                        byte[] sigBytes = sig.sign();
                        if (sigBytes.length > 0) {
                            sigStr = toHexString(sigBytes);
                        }
                    } else if (aliasUser.equals("key5")){
                        // for key of algorithm DSA
                        KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ksCustom.getEntry(aliasUser, null);
                        byte[] data = msgToSign.getBytes(StandardCharsets.UTF_8);
                        Signature sig = Signature.getInstance("SHA256withDSA");
                        sig.initSign(pkEntry.getPrivateKey());
                        sig.update(data);
                        byte[] sigBytes = sig.sign();
                        if (sigBytes.length > 0) {
                            sigStr = toHexString(sigBytes);
                        }
                    }
                }
            } else {
                Toast.makeText(this, "No message to sign. Enter message to sign", Toast.LENGTH_SHORT).show();
            }
        } else {
            Toast.makeText(this, "Key alias not found. Try again", Toast.LENGTH_SHORT).show();
        }

        intent.putExtra("RESULT", sigStr);
        setResult(RESULT_OK, intent);
        finish();
        msgToSign = null;
        aliasUser = null;
        sigStr = null;
    }

    // handle permission request from user
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == REQUEST_READ_PERMISSION) {// If request is cancelled, the result arrays are empty.
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Toast.makeText(this, "Permission Granted from user", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Permission Denied from user", Toast.LENGTH_SHORT).show();
            }
        }
    }

    // convert bytes to hex
    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();

        for (byte aByte : bytes) {
            String hex = Integer.toHexString(0xFF & aByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }


    private class EditTextWatcher implements TextWatcher {
        EditText mEditTextView;
        Context mContext;

        EditTextWatcher(Context context, EditText mEditTextView) {
            super();
            this.mContext = context;
            this.mEditTextView = mEditTextView;
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {

        }

        // on text changed, get message to sign from user
        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            if (mEditTextView.equals(msg)) {
                msgToSign = mEditTextView.getText().toString();
            } else if (mEditTextView.equals(aliasEntry)) {
                aliasUser = mEditTextView.getText().toString();
            }

        }

        @Override
        public void afterTextChanged(Editable s) {

        }
    }
}
