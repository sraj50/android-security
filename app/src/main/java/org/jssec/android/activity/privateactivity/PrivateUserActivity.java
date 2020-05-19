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
import android.app.Activity;
import android.content.Intent;

import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.view.View;
import android.view.WindowManager;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.IOException;

import java.io.Serializable;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import java.security.cert.*;


public class PrivateUserActivity extends Activity {

    public static class keystore_info implements Serializable {
        String keystore_file;
        String password_val;

        public void keystore_info(){
            this.keystore_file="";
            this.password_val="";
        }
        public void setKeystore_file(String key_file) {
            this.keystore_file = key_file;
        }

        public void setPassword_val(String pass_val) {
            this.password_val = pass_val;
        }

        public String getPassword_val() {
            return password_val;
        }

        public String getKeystore_file() {
            return keystore_file;
        }


    }


    private static final int REQUEST_CODE = 1;

    // Key to save the state
    private static final String KEY_DUMMY_PASSWORD = "KEY_DUMMY_PASSWORD";

    // View inside Activity
    private EditText mPasswordEdit;
    private CheckBox mPasswordDisplayCheck;

    // Flag to show whether password is dummy display or not
    private boolean mIsDummyPassword;


    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.user_activity);
        // Set Disabling Screen Capture
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);

        // Get View
        mPasswordEdit = (EditText) findViewById(R.id.password_edit);
        mPasswordDisplayCheck =
                (CheckBox) findViewById(R.id.password_display_check);

        // Whether last Input password exist or not.
        if (getPreviousPassword() != null) {
            // In the case there is the last input password in
            // an initial display, display the fixed digit numbers of black dot
            // as dummy in order not that the digits number of last password
            // is guessed.

            // Display should be dummy password.
            mPasswordEdit.setText("**********");
            // To clear the dummy password when inputting password, set text
            // change listener.
            mPasswordEdit.addTextChangedListener(new PasswordEditTextWatcher());
            // Set dummy password flag
            mIsDummyPassword = true;
        }

        // Set a listner to change check state of password display option.
        mPasswordDisplayCheck.setOnCheckedChangeListener(new OnPasswordDisplayCheckedChangeListener());


    }

    @Override
    public void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);

        // Unnecessary when specifying not to regenerate Activity by the change in
        // screen aspect ratio.
        // Save Activity state
        outState.putBoolean(KEY_DUMMY_PASSWORD, mIsDummyPassword);
    }

    @Override
    public void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);

        // Unnecessary when specifying not to regenerate Activity by the change in
        // screen aspect ratio.
        // Restore Activity state
        mIsDummyPassword = savedInstanceState.getBoolean(KEY_DUMMY_PASSWORD);
    }

    /**
     * Process in case password is input
     */
    private class PasswordEditTextWatcher implements TextWatcher {

        public void beforeTextChanged(CharSequence s, int start, int count,
                                      int after) {
            // Not used
        }

        public void onTextChanged(CharSequence s, int start, int before,
                                  int count) {
            // When last Input password is displayed as dummy,
            // in the case an user tries to input password, Clear the last
            // input password, and treat new user input as new password.
            if (mIsDummyPassword) {
                // Set dummy password flag
                mIsDummyPassword = false;
                // Trim space
                CharSequence work = s.subSequence(start, start + count);
                mPasswordEdit.setText(work);
                // Cursor position goes back the beginning, so bring it at the end.
                mPasswordEdit.setSelection(work.length());
            }
        }

        public void afterTextChanged(Editable s) {
            // Not used
        }

    }


    /**
     * Process when check of password display option is changed.
     */
    private class OnPasswordDisplayCheckedChangeListener
            implements CompoundButton.OnCheckedChangeListener {

        public void onCheckedChanged(CompoundButton buttonView,
                                     boolean isChecked) {
            // When the dummy password is displayed and the
            // "Show password" button is pressed, clear the last input
            // password and provide the state for new password input.
            if (mIsDummyPassword && isChecked) {
                // Set dummy password flag
                mIsDummyPassword = false;
                // Set password empty
                mPasswordEdit.setText(null);
            }

            // Cursor position goes back the beginning, so memorize the current
            // cursor position.
            int pos = mPasswordEdit.getSelectionStart();

            // Provide the option to display the password in a
            // plain text
            // Create InputType
            int type = InputType.TYPE_CLASS_TEXT;
            if (isChecked) {
                // Plain display when check is ON.
                type |= InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD;
            } else {
                // Masked display when check is OFF.
                type |= InputType.TYPE_TEXT_VARIATION_PASSWORD;
            }

            // Set InputType to password EditText
            mPasswordEdit.setInputType(type);

            // Set cursor position
            mPasswordEdit.setSelection(pos);
        }

    }

    // Implement the following method depends on application

    /**
     * Get the last Input password
     *
     * @return Last Input password
     */
    private String getPreviousPassword() {
        // When need to restore the saved password, return password character
        // string
        // For the case password is not saved, return null
        return "fit5003";
    }

    /**
     * Process when cancel button is clicked
     *
     * @param view
     */
    public void onClickCancelButton(View view) {
        // Close Activity
        finish();
    }

    /**
     * Process when OK button is clicked
     *
     * @param view
     */
    public void onClickOkButton(View view){
        // Execute necessary processes like saving password or using for
        // authentication
        EditText keystore_f = (EditText) findViewById(R.id.keyfile);
        String password = null;

        if (mIsDummyPassword) {
            // When dummy password is displayed till the final moment, grant last
            // input password as fixed password.
            password = getPreviousPassword();
        } else {
            // In case of not dummy password display, grant the user input
            // password as fixed password.
            password = mPasswordEdit.getText().toString();
        }

        // Display password by Toast
        //Toast.makeText(this, "password is \"" + password + "\"", Toast.LENGTH_SHORT).show();

        keystore_info ks_f= new keystore_info();

        ks_f.setKeystore_file("default");
        ks_f.setPassword_val(mPasswordEdit.getText().toString());


        // Do not set the FLAG_ACTIVITY_NEW_TASK flag
        // for intents to start an activity.
        // Use the explicit Intents with the class
        // specified to call an activity in the same application.
        Intent i = new Intent(this, PrivateActivity.class);
    try {


        // Sensitive information can be sent only by putExtra()
        // since the destination activity is in the same application.

        i.putExtra("CL_k", ks_f);

        // must change for setActivityForResult()
//        startActivity(i);
        startActivityForResult(i, REQUEST_CODE);

    }catch (RuntimeException  e){
        e.printStackTrace();
    }
        // Close Activity
        //finish();
    }



    //----------------------------------------------------------------------

    public void onUseActivityClick(View view) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {

        EditText keystore_f = (EditText) findViewById(R.id.keyfile);
        EditText passwd_name = (EditText) findViewById(R.id.password_edit);


        // get user password and file input stream

        keystore_info ks_f= new keystore_info();
        ks_f.setKeystore_file(keystore_f.getText().toString());
        ks_f.setPassword_val(passwd_name.getText().toString());


        Intent intent = new Intent(this, PrivateActivity.class);
        
        intent.putExtra("CL_k", ks_f);
        
        startActivityForResult(intent, REQUEST_CODE);

    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if (resultCode != RESULT_OK) return;
        
        switch (requestCode) {
        case REQUEST_CODE:
            String result = data.getStringExtra("RESULT");
                        
            //  Handle the received data carefully and securely,
            // even though the data comes from an activity within the same
            // application.

            Toast.makeText(this,
                           String.format("Received result: \"%s\"", result),
                           Toast.LENGTH_LONG).show();
            break;
        }
    }
}
