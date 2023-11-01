# Makefile - based on https://github.com/Terrahop/react-native-rust-demo

NAME = libethers_ffi
LIB = $(NAME).a
SO = $(NAME).so
ARCHS_ANDROID = aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
NDK_STANDALONE = ~/Library/Android/sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/darwin-x86_64
ANDROID_DEST = ./ethers-rs-mobile/android/jniLibs
IOS_DEST = ./ethers-rs-mobile/ios
CARGO_PARAMS = --no-default-features 

ARCHS_IOS = aarch64-apple-ios
ARCHS_IOS_SIM = x86_64-apple-ios aarch64-apple-ios-sim
IOS_LIB = $(NAME).xcframework
XCFRAMEWORK = $(NAME)-iOS.xcframework
IOS_PLATFORMS = iphoneos iphonesimulator

TARGET_DIR = ../target

all: android ios

android-setup:
	rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

android-build: $(ARCHS_ANDROID)

ios: $(IOS_LIB)

clean:
	rm -rf $(IOS_DEST)
	rm -rf $(ANDROID_DEST)
	rm -rf $(TARGET_DIR)

android: android-setup android-build
	mkdir -p $(ANDROID_DEST)
	mkdir -p $(ANDROID_DEST)/x86
	mkdir -p $(ANDROID_DEST)/x86_64
	mkdir -p $(ANDROID_DEST)/arm64-v8a
	mkdir -p $(ANDROID_DEST)/armeabi
	mkdir -p $(ANDROID_DEST)/armeabi-v7a

	cp $(TARGET_DIR)/i686-linux-android/release/$(SO) ${ANDROID_DEST}/x86/$(SO)
	cp $(TARGET_DIR)/x86_64-linux-android/release/$(SO) ${ANDROID_DEST}/x86_64/$(SO)
	cp $(TARGET_DIR)/aarch64-linux-android/release/$(SO) ${ANDROID_DEST}/arm64-v8a/$(SO)
	cp $(TARGET_DIR)/armv7-linux-androideabi/release/$(SO) ${ANDROID_DEST}/armeabi-v7a/$(SO)

aarch64-linux-android:
	PATH=$(PATH):$(NDK_STANDALONE)/arm64/bin \
	CC=$@-clang \
	CXX=$@-clang++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

armv7-linux-androideabi:
	PATH=$(PATH):$(NDK_STANDALONE)/arm/bin \
	CC=armv7a-linux-androideabi-gcc \
	CXX=armv7a-linux-androideabi-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

i686-linux-android:
	PATH=$(PATH):$(NDK_STANDALONE)/x86/bin \
	CC=$@-clang \
	CXX=$@-clang++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

x86_64-linux-android:
	PATH=$(PATH):$(NDK_STANDALONE)/x86_64/bin \
	CC=$@-clang \
	CXX=$@-clang++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

iphoneos: $(ARCHS_IOS)
	mkdir -p $(TARGET_DIR)/$@
	lipo -create -output $(TARGET_DIR)/$@/$(LIB) $(foreach arch,$(ARCHS_IOS),$(wildcard $(TARGET_DIR)/$(arch)/release/$(LIB)))

iphonesimulator: $(ARCHS_IOS_SIM)
	mkdir -p $(TARGET_DIR)/$@
	lipo -create -output $(TARGET_DIR)/$@/$(LIB) $(foreach arch,$(ARCHS_IOS_SIM),$(wildcard $(TARGET_DIR)/$(arch)/release/$(LIB)))

.PHONY: $(ARCHS_IOS) $(ARCHS_IOS_SIM)
$(ARCHS_IOS) $(ARCHS_IOS_SIM): %:
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

$(IOS_LIB): $(IOS_PLATFORMS)
	mkdir -p $(IOS_DEST)
	cbindgen --config cbindgen.toml --crate ethers-ffi --output $(TARGET_DIR)/$(NAME).h
	xcodebuild -create-xcframework -library $(TARGET_DIR)/iphoneos/$(LIB) -headers $(TARGET_DIR)/$(NAME).h -library $(TARGET_DIR)/iphonesimulator/$(LIB) -headers $(TARGET_DIR)/$(NAME).h -output $(IOS_DEST)/$@ 