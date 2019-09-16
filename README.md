# Secure Device Storage - Android

## Storing Credentials Securely on Android Devices

[![API](https://img.shields.io/badge/API-19%2B-blue.svg?style=flat)](https://android-arsenal.com/api?level=19)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) 
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)



### Introduction

Storing credentials securely on a device is in many occasions necessary. You probably don't want to rely only on the separation of processes of the Android OS but make sure the stored values are also encrypted.
To make that possible we have combined the Android Keystore and the SharedPreferences. The keystore is used for generating cryptographic keys, the values are then encrypted with these keys and subsequently securely stored in the SharedPreferences.

The secure part about this solution is that those generated keys are never exposed to the kernel when the device is equipped with a “Trusted Execution Environment”. A so called TEE is a secure area inside the main processor of a smartphone which runs code isolated from other processes. That means even if the device gets compromised or hacked those keys can’t be extracted. Already a lot of modern Android phones out there are equipped with a TEE (mostly because it’s often used to play DRM protected material) and it even is a requirement for Google’s Android Nougat certification — so every phone running Android Nougat and later will come with a TEE installed.

### Supported API's

__Symmetric__ key generation and storage in the Android KeyStore is supported from __Android 6.0 (API Level 23) onwards.__
__Asymmetric__ key generation and storage in the Android KeyStore is supported from __Android 4.3 (API Level 18) onwards.__

To support more devices SecureStorage uses for now the asymmetric key generation, which in the case of storing simple credentials is very secure and the potential lack of speed in contrast to symmetric key generation, is not noticeable. Nevertheless, make sure to move the execution into a background thread as encryption does take a little time.

### Usage

Add the library to your project settings.gradle:

```groovy
include ':app', ':securestoragelibrary'
```

Add the library to your apps build.gradle:

```groovy
implementation project(':securestoragelibrary')
```

Get a handle to shared preferences:
```java
SharedPreferences preferences = (SharedPreferences) new SecurePreferences(context, "NAME_PREFERENCES_FILE");
```

Then, use it like the [SharedPreferences](https://developer.android.com/training/data-storage/shared-preferences#WriteSharedPreference) APIs


Everything about the cryptographic keys such as generating, maintaining and usage is handled internally by the module, so you do not need to worry about it.

Note: getAll() method not supported yet. You can propose an implementation.

### Error handling
The library throws for everything a [SecurityException](https://developer.android.com/reference/java/lang/SecurityException). You can change it to [Log](https://developer.android.com/reference/android/util/Log) class.

### Want to know more:

These links cover security aspect of the android keystore:
<https://developer.android.com/training/articles/keystore.html#SecurityFeatures>
<https://source.android.com/security/keystore/>
<https://codingquestion.blogspot.de/2016/09/how-to-use-android-keystore-api-with.html>
<http://nelenkov.blogspot.de/2012/05/storing-application-secrets-in-androids.html>
<http://nelenkov.blogspot.de/2015/06/keystore-redesign-in-android-m.html>
<http://www.androidauthority.com/use-android-keystore-store-passwords-sensitive-information-623779/>  

This link covers security aspect of the android storage:
<https://developer.android.com/guide/topics/data/data-storage.html>
<http://stackoverflow.com/a/26077852/3392276>

### License:
-------
    Copyright (C) 2019 SoryApps & adorsys GmbH & Co. KG
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
       https://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

