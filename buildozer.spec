[app]
title = CamFinder
package.name = camfinder
package.domain = org.camfinder

source.dir = .
source.include_exts = py,png,jpg,kv,atlas

version = 1.0.0

requirements = python3,kivy

orientation = portrait
fullscreen = 0

# صلاحيات أندرويد المطلوبة للبحث على الشبكة (لا صلاحيات كاميرا أو جهات اتصال)
android.permissions = INTERNET,ACCESS_NETWORK_STATE,ACCESS_WIFI_STATE,WRITE_EXTERNAL_STORAGE,READ_EXTERNAL_STORAGE

android.api = 33
android.minapi = 21
android.ndk_api = 21
android.accept_sdk_license = True
android.archs = arm64-v8a,armeabi-v7a

[buildozer]
log_level = 2
warn_on_root = 0
