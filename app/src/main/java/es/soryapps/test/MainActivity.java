package es.soryapps.test;

import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;

import java.util.HashSet;
import java.util.Set;

import de.adorsys.android.securestoragelibrary.SecurePreferences;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "TEST";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences preferences;
        SharedPreferences.Editor editor;
        Set<String> testSet;

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        preferences = (SharedPreferences) new SecurePreferences(this, "test");

        editor = preferences.edit();
        editor.putString("stringKey", "stringValue");
        editor.putBoolean("booleanKey", true);
        editor.putFloat("floatKey", 1f);
        editor.putInt("intKey", 1);
        editor.putLong("longKey", 1L);
        testSet = new HashSet<>();
        testSet.add("setValue");
        editor.putStringSet("setKey", testSet);
        editor.apply();

        Log.e(TAG, "Get String: " + preferences.getString("stringKey", "default"));
        Log.e(TAG, "Get Boolean: " + preferences.getBoolean("booleanKey", false));
        Log.e(TAG, "Get Float: " + preferences.getFloat("floatKey", -1f));
        Log.e(TAG, "Get Int: " + preferences.getInt("intKey", -1));
        Log.e(TAG, "Get Long: " + preferences.getLong("longKey", -1L));
        testSet = preferences.getStringSet("setKey", null);
        Log.e(TAG, "Get Set size: " + (testSet != null ? testSet.size() : -1) );

        Log.e(TAG, "Contains stringKey: " + preferences.contains("stringKey"));
        editor = preferences.edit();
        editor.remove("stringKey");
        editor.apply();
        Log.e(TAG, "Contains stringKey: " + preferences.contains("stringKey"));
        Log.e(TAG, "Contains booleanKey: " + preferences.contains("booleanKey"));
        editor = preferences.edit();
        editor.clear();
        editor.apply();
        Log.e(TAG, "Contains booleanKey: " + preferences.contains("booleanKey"));
    }
}
