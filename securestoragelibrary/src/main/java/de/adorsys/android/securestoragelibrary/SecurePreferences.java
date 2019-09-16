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

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;

import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import static de.adorsys.android.securestoragelibrary.SecureStorageException.ExceptionType.CRYPTO_EXCEPTION;

/**
 * Handles every use case for the developer using Secure Storage.
 * Encryption, Decryption, Storage, Removal etc.
 */
public final class SecurePreferences implements SharedPreferences {
    private static final String HASH = "SHA-256";

    private static final String PREFS_ID_PREFIX = "SECST";

    private SharedPreferences preferences;
    private Context appContext;
    private KeystoreTool kst;

    public SecurePreferences(@NonNull Context context, @NonNull String preferencesId)
    {  init(context, preferencesId);  }
    private void init(@NonNull Context context, @NonNull String preferencesId)
    {
        context = context.getApplicationContext();
        appContext = context;
        preferences = context.getSharedPreferences((PREFS_ID_PREFIX + preferencesId), Context.MODE_PRIVATE);

        try
        {  kst = new KeystoreTool(preferencesId);  }
        catch(SecureStorageException e)
        {
            // Alt: Log.e()
            throw new SecurityException("Error using Secure Preferences (start)");
        }
    }

	// Hashing the key makes it difficult to implement getAll()
    private static String hashKey(@NonNull String key)
    {
        final MessageDigest messageDigest;

        try
        {
            messageDigest = MessageDigest.getInstance(HASH);
            messageDigest.update(key.getBytes());
            return Base64.encodeToString(messageDigest.digest(), Base64.NO_WRAP);
        }
        catch(NoSuchAlgorithmException e)
        {  return key;  }
    }

    // Not supported yet.
    // You can propose an implementation.
    @Override
    public Map<String, ?> getAll() {
        return null;
    }

    @Nullable
    @Override
    public String getString(@NonNull String key, @Nullable String defValue)
    {
        String cryptValue;

        cryptValue = preferences.getString( hashKey(key), null);
        try
        {
            if(cryptValue != null && !TextUtils.isEmpty(cryptValue))
            {  return kst.decryptMessage(cryptValue);  }
        }
        catch(SecureStorageException e)
        {}
        return defValue;
    }

    @Nullable
    @Override
    public Set<String> getStringSet(@NonNull String key, @Nullable Set<String> defValues)
    {
        Set<String> cryptSet;
        Set<String> decrSet;

        try
        {  cryptSet = preferences.getStringSet( hashKey(key), null);  }
        catch(ClassCastException e)
        {  cryptSet = null;  }

        if(cryptSet != null)
        {
            decrSet = new HashSet<String>(cryptSet.size());
            try
            {
                for(String valorCifrado : cryptSet)
                {  decrSet.add(kst.decryptMessage(valorCifrado));  }
                return decrSet;
            }
            catch(SecureStorageException e)
            {}
        }
        return defValues;
    }

    @SuppressWarnings("unchecked")
    private <T> T getValue(@NonNull String key, T defValue, @NonNull Class<T> tipo)
    {
        String decrValue;

        decrValue = getString(key, null);

        if(decrValue != null && !TextUtils.isEmpty(decrValue))
        {
            try
            {  return (T) tipo.getMethod("valueOf", new Class[] { String.class }).invoke(null, decrValue);  }
            catch(NumberFormatException|IllegalAccessException|InvocationTargetException|NoSuchMethodException e)
            {}
        }
        return defValue;
    }

    @Override
    public int getInt(@NonNull String key, int defValue)
    {  return getValue(key, defValue, Integer.class);  }

    @Override
    public long getLong(@NonNull String key, long defValue)
    {  return getValue(key, defValue, Long.class);  }

    @Override
    public float getFloat(@NonNull String key, float defValue)
    {  return getValue(key, defValue, Float.class);  }

    @Override
    public boolean getBoolean(@NonNull String key, boolean defValue)
    {  return getValue(key, defValue, Boolean.class);  }

    @Override
    public boolean contains(@NonNull String key)
    {
        try
        {  return preferences.contains( hashKey(key) ) && kst.keyPairExists();  }
        catch(SecureStorageException e)
        {  return false;  }
    }

    @Override
    public Editor edit()
    {  return new Editor();  }

    @Override
    public void registerOnSharedPreferenceChangeListener(@NonNull OnSharedPreferenceChangeListener listener)
    {  preferences.registerOnSharedPreferenceChangeListener(listener);  }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(@NonNull OnSharedPreferenceChangeListener listener)
    {  preferences.unregisterOnSharedPreferenceChangeListener(listener);  }

    public final class Editor implements SharedPreferences.Editor
    {
        private SharedPreferences.Editor editor;

        @SuppressLint("CommitPrefEdits")
        private Editor()
        {  editor = preferences.edit();  }

        private String cryptString(@NonNull String value)
        {
            String cryptValue;

            try
            {
                if(!kst.keyPairExists())
                {  kst.generateKeyPair(appContext);  }

                cryptValue = kst.encryptMessage(value);

                if(cryptValue == null || TextUtils.isEmpty(cryptValue))
                {  throw new SecureStorageException("Problem during Encryption", null, CRYPTO_EXCEPTION);  }
            }
            catch(SecureStorageException e)
            {
                // Alt: Log.e()
                throw new SecurityException("Error using Secure Preferences (encryption)");
            }
            return cryptValue;
        }

        private void addString(@NonNull String key, @Nullable String value)
        {
            if(value != null)
            {  editor.putString(hashKey(key), cryptString(value));  }
        }

        private <T> void setValue(@NonNull String key, T valor)
        {  addString(key, String.valueOf(valor));  }

        @Override
        public SharedPreferences.Editor putString(@NonNull String key, @Nullable String value)
        {  addString(key, value);  return this;  }

        @Override
        public SharedPreferences.Editor putStringSet(@NonNull String key, @Nullable Set<String> values)
        {
            final Set<String> cryptValues;

            if(values != null)
            {
                cryptValues = new HashSet<String>(values.size());
                for(String value : values)
                {
                    if(value != null)
                    {  cryptValues.add(cryptString(value));  }
                }
                if(!cryptValues.isEmpty())
                {  editor.putStringSet(hashKey(key), cryptValues);  }
            }
            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(@NonNull String key, int value)
        {  setValue(key, value);  return this;  }

        @Override
        public SharedPreferences.Editor putLong(@NonNull String key, long value)
        {  setValue(key, value);  return this;  }

        @Override
        public SharedPreferences.Editor putFloat(@NonNull String key, float value)
        {  setValue(key, value);  return this;  }

        @Override
        public SharedPreferences.Editor putBoolean(@NonNull String key, boolean value)
        {  setValue(key, value);  return this;  }

        @Override
        public SharedPreferences.Editor remove(@NonNull String key)
        {  editor.remove( hashKey(key) );  return this;  }

        @Override
        public SharedPreferences.Editor clear()
        {
            try
            {
                if(kst.keyPairExists())
                {  kst.deleteKeyPair();  }

                editor.clear();
                return this;
            }
            catch(SecureStorageException e)
            // Alt: Log.e()
            {  throw new SecurityException("Error using Secure Preferences (clear)");  }
        }

        @Override
        public boolean commit()
        {  return editor.commit();  }

        @Override
        public void apply()
        {  editor.apply();  }
    }
}